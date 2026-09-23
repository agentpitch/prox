package httpclient

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testRequest(t *testing.T, rawURL string) *Request {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return &Request{URL: parsed, Header: Header{"accept": "application/octet-stream"}}
}

func TestStreamingResponseAndHeaders(t *testing.T) {
	payload := strings.Repeat("streamed-data", 20_000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/octet-stream" || r.URL.RawQuery != "value=a%2Fb" {
			t.Errorf("request headers/query: %v %s", r.Header, r.URL.RawQuery)
		}
		w.Header().Set("X-RateLimit-Reset", "12345")
		_, _ = io.WriteString(w, payload)
	}))
	defer server.Close()
	client := &Client{Timeout: 5 * time.Second}
	response, err := client.Do(context.Background(), testRequest(t, server.URL+"/file?value=a%2Fb"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("X-RATELIMIT-RESET") != "12345" {
		t.Fatalf("response = %#v", response)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil || string(content) != payload {
		t.Fatalf("stream = %d bytes, %v", len(content), err)
	}
}

func TestRedirectPolicyRunsBeforeDestination(t *testing.T) {
	var reached atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer origin.Close()
	denied := errors.New("destination denied")
	client := &Client{CheckRedirect: func(target *url.URL, redirects int) error {
		if target.String() != destination.URL || redirects != 1 {
			t.Errorf("redirect = %s, %d", target, redirects)
		}
		return denied
	}}
	_, err := client.Do(context.Background(), testRequest(t, origin.URL))
	if !errors.Is(err, denied) || reached.Load() != 0 {
		t.Fatalf("error=%v destination requests=%d", err, reached.Load())
	}
}

func TestRelativeRedirectAndRedirectLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/loop" {
			http.Redirect(w, r, "/loop", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "end")
	}))
	defer server.Close()
	client := &Client{CheckRedirect: func(*url.URL, int) error { return nil }}
	response, err := client.Do(context.Background(), testRequest(t, server.URL+"/start"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(content) != "end" {
		t.Fatalf("content=%q error=%v", content, err)
	}
	if _, err := client.Do(context.Background(), testRequest(t, server.URL+"/loop")); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("redirect loop error = %v", err)
	}
}

func TestUntrustedCertificateRejected(t *testing.T) {
	var reached atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	client := &Client{Timeout: 5 * time.Second}
	response, err := client.Do(context.Background(), testRequest(t, server.URL))
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("accepted an untrusted TLS certificate")
	}
	if reached.Load() != 0 {
		t.Fatal("sent HTTP request through untrusted TLS")
	}
}

func TestHTTPSRedirectCannotDowngrade(t *testing.T) {
	original, _ := url.Parse("https://github.com/update")
	if _, err := redirectDestination(original, "http://github.com/update"); err == nil {
		t.Fatal("accepted HTTPS downgrade")
	}
	if next, err := redirectDestination(original, "/asset"); err != nil || next.String() != "https://github.com/asset" {
		t.Fatalf("relative HTTPS redirect = %v, %v", next, err)
	}
}

func TestCancelBeforeResponseHeaders(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-entered; cancel() }()
	started := time.Now()
	_, err := (&Client{Timeout: 5 * time.Second}).Do(ctx, testRequest(t, server.URL))
	if !errors.Is(err, context.Canceled) || time.Since(started) > 2*time.Second {
		t.Fatalf("cancellation error=%v elapsed=%v", err, time.Since(started))
	}
}

func TestTimeoutCoversBodyRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	started := time.Now()
	response, err := (&Client{Timeout: 200 * time.Millisecond}).Do(context.Background(), testRequest(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, err = io.ReadAll(response.Body)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
		t.Fatalf("body timeout error=%v elapsed=%v", err, time.Since(started))
	}
}

func TestCloseCancelsBlockedRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	response, err := (&Client{Timeout: 5 * time.Second}).Do(context.Background(), testRequest(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, readErr := response.Body.Read(make([]byte, 8192)); done <- readErr }()
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read succeeded after close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not cancel read")
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTimeoutClosesAnUnreadBody(t *testing.T) {
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(closed)
	}))
	defer server.Close()
	response, err := (&Client{Timeout: 100 * time.Millisecond}).Do(context.Background(), testRequest(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout did not close an unread response")
	}
}

func TestTruncatedResponseFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = io.WriteString(w, "short")
	}))
	defer server.Close()
	response, err := (&Client{Timeout: 5 * time.Second}).Do(context.Background(), testRequest(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err == nil {
		t.Fatalf("accepted truncated response (%d bytes)", len(content))
	}
}
