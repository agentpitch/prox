//go:build windows

package httpclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNativeRequestStateReleasedAfterEachClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.Close {
			t.Error("native request permits an idle keep-alive connection")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	client := &Client{Timeout: 5 * time.Second}
	for index := 0; index < 50; index++ {
		response, err := client.Do(context.Background(), testRequest(t, server.URL))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		requests.Range(func(key, value any) bool {
			t.Errorf("native callback state remains after close %d: %v", index, key)
			return false
		})
	}
}

func TestNativeNamedProxyReceivesRequest(t *testing.T) {
	seen := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.RequestURI
		_, _ = io.WriteString(w, "from-proxy")
	}))
	defer proxy.Close()
	for _, name := range []string{"http_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(name, "")
	}
	t.Setenv("HTTP_PROXY", proxy.URL)
	response, err := (&Client{Timeout: 2 * time.Second}).Do(context.Background(), testRequest(t, "http://update.invalid/file"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil || string(content) != "from-proxy" {
		t.Fatalf("proxy response=%q error=%v", content, err)
	}
	if got := <-seen; got != "http://update.invalid/file" {
		t.Fatalf("proxy request URI=%q", got)
	}
}
