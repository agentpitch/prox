package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
)

type fixedConnDialer struct{ conn net.Conn }

func (d fixedConnDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func TestProxyHandshakeCancellationClosesSocket(t *testing.T) {
	for _, kind := range []string{"http", "socks5"} {
		t.Run(kind, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			defer client.Close()
			dialer, err := wrapDialer(fixedConnDialer{client}, config.ProxyProfile{Type: kind})
			if err != nil {
				t.Fatal(err)
			}
			// The peer deliberately accepts the greeting without responding. This
			// exercises cancellation after the parent dial already succeeded.
			greeting := make(chan struct{})
			go func() {
				buf := make([]byte, 4096)
				_, _ = server.Read(buf)
				close(greeting)
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
				if conn != nil {
					_ = conn.Close()
				}
				done <- err
			}()
			select {
			case <-greeting:
			case <-time.After(time.Second):
				t.Fatal("proxy did not receive greeting")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled handshake returned %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation left the handshake blocked")
			}
		})
	}
}

func TestHTTPConnectPreservesPayloadAndDetachesDialCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nX-Test: value\r\n\r\npayload")
		_, _ = io.WriteString(server, "-after-cancel")
		_ = server.Close()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialer := &httpConnectDialer{parent: fixedConnDialer{client}}
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "payload-after-cancel" {
		t.Fatalf("tunnel bytes after dial cancellation = %q, %v", got, err)
	}
}

func TestHTTPConnectBoundsResponseHeaders(t *testing.T) {
	for _, response := range []string{
		"HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", maxConnectResponseBytes+1),
		"HTTP/1.1 200 OK\r\n" + strings.Repeat("X-Test: value\r\n", maxConnectResponseBytes/10),
	} {
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			br := bufio.NewReader(server)
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			_, _ = io.WriteString(server, response)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		dialer := &httpConnectDialer{parent: fixedConnDialer{client}}
		conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
		cancel()
		_ = client.Close()
		if conn != nil {
			_ = conn.Close()
		}
		<-done
		if err == nil || !strings.Contains(err.Error(), "headers exceed") {
			t.Fatalf("oversized headers error = %v", err)
		}
	}
}

func TestBufferedConnReleasesPrefixAndPreservesBytes(t *testing.T) {
	for _, kind := range []string{"sniff", "connect"} {
		t.Run(kind, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				_, _ = io.WriteString(server, "prefix")
				_, _ = io.WriteString(server, "payload")
				_ = server.Close()
			}()
			br := bufio.NewReaderSize(client, 64<<10)
			if _, err := br.Peek(6); err != nil {
				t.Fatal(err)
			}
			var reader io.Reader
			var released func() bool
			if kind == "sniff" {
				conn := &prefixedConn{Conn: client, Reader: br}
				reader = conn
				released = func() bool { return conn.Reader == nil }
			} else {
				conn := &bufferedConn{Conn: client, r: br}
				reader = conn
				released = func() bool { return conn.r == nil }
			}
			got, err := io.ReadAll(reader)
			if err != nil || string(got) != "prefixpayload" {
				t.Fatalf("read = %q, %v", got, err)
			}
			if !released() {
				t.Fatal("drained prefix buffer is retained")
			}
		})
	}
}
