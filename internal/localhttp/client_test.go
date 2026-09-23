package localhttp

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testOptions() Options {
	return Options{Timeout: time.Second, DialTimeout: time.Second, MaxHeaderBytes: 1024, MaxBodyBytes: 32}
}

func TestReadResponseFramingAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name, raw, body string
		fail            bool
	}{
		{"length", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "ok", false},
		{"close", "HTTP/1.0 200 OK\r\n\r\nok", "ok", false},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=value\r\nok\r\n0\r\nX-Trailer: fine\r\n\r\n", "ok", false},
		{"informational", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "ok", false},
		{"truncated", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok", "", true},
		{"oversized", "HTTP/1.1 200 OK\r\nContent-Length: 33\r\n\r\n", "", true},
		{"oversized close", "HTTP/1.1 200 OK\r\n\r\n" + strings.Repeat("x", 33), "", true},
		{"oversized chunk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n21\r\n", "", true},
		{"oversized header", "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("x", 1024), "", true},
		{"ambiguous framing", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n", "", true},
		{"duplicate length", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok", "", true},
		{"negative length", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", "", true},
		{"unknown encoding", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", "", true},
		{"bad chunk ending", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nokXX0\r\n\r\n", "", true},
		{"header folding", "HTTP/1.1 200 OK\r\nX: foo\r\n bar\r\n\r\n", "", true},
		{"upgrade", "HTTP/1.1 101 Switching Protocols\r\n\r\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, err := readResponse(bufio.NewReader(strings.NewReader(tc.raw)), testOptions(), "GET")
			if (err != nil) != tc.fail || (!tc.fail && (response.StatusCode != 200 || string(response.Body) != tc.body)) {
				t.Fatalf("response=%+v error=%v", response, err)
			}
		})
	}
}

func TestRequestDoesNotFollowRedirectOrRetryWrites(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "PUT" || r.Header.Get("X-Test") != "yes" || r.Header.Get("Connection") != "close" {
			t.Errorf("unexpected request: %+v", r)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "hello" {
			t.Errorf("body %q", body)
		}
		w.Header().Set("Location", "/again")
		w.WriteHeader(307)
	}))
	defer server.Close()
	response, err := Request(context.Background(), testOptions(), "PUT", server.URL+"/config", map[string]string{"X-Test": "yes"}, []byte("hello"))
	if err != nil || response.StatusCode != 307 || calls.Load() != 1 {
		t.Fatalf("response=%+v err=%v calls=%d", response, err, calls.Load())
	}
}

func TestRequestRejectsUnsafeTargetsAndHeaders(t *testing.T) {
	for _, raw := range []string{
		"https://127.0.0.1/", "http://example.com/", "http://192.168.1.1/", "http://[::1%25lo]/", "http://user@127.0.0.1/", "http://127.0.0.1:0/", "http://127.0.0.1/#fragment",
	} {
		if _, err := Request(context.Background(), testOptions(), "GET", raw, nil, nil); err == nil {
			t.Errorf("accepted unsafe URL %q", raw)
		}
	}
	for _, headers := range []map[string]string{{"Content-Length": "10"}, {"X": "ok\r\nEvil: yes"}, {"X Y": "bad"}} {
		if _, err := Request(context.Background(), testOptions(), "GET", "http://127.0.0.1:1/", headers, nil); err == nil {
			t.Errorf("accepted invalid headers %v", headers)
		}
	}
}

func TestRequestCancellationInterruptsBodyRead(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := Request(ctx, testOptions(), "GET", server.URL, nil, nil)
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled request succeeded")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancel did not interrupt body read")
	}
}

func TestLocalhostUsesIPv6WhenIPv4DoesNotListen(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	response, err := Request(context.Background(), testOptions(), "GET", "http://localhost:"+port+"/", nil, nil)
	if err != nil || string(response.Body) != "ok" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
}
