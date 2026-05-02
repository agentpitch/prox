package proxy

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestPeekAndSniffHTTPDoesNotWaitForMaxBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n"))
		errCh <- err
	}()

	start := time.Now()
	_, got, err := PeekAndSniff(server, 4096, 2*time.Second)
	if err != nil {
		t.Fatalf("PeekAndSniff failed: %v", err)
	}
	if got.Hostname != "example.com" || got.Protocol != "http" {
		t.Fatalf("sniff result = %+v, want http example.com", got)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("sniff waited too long: %s", elapsed)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("client write failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client write did not complete")
	}
}

func TestPeekAndSniffTLSSNIDoesNotWaitForMaxBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		tlsClient := tls.Client(client, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "Example.COM",
		})
		_ = tlsClient.SetDeadline(time.Now().Add(2 * time.Second))
		errCh <- tlsClient.Handshake()
	}()

	start := time.Now()
	_, got, err := PeekAndSniff(server, 4096, 2*time.Second)
	if err != nil {
		t.Fatalf("PeekAndSniff failed: %v", err)
	}
	if got.Hostname != "example.com" || got.Protocol != "tls" {
		t.Fatalf("sniff result = %+v, want tls example.com", got)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("sniff waited too long: %s", elapsed)
	}

	_ = server.Close()
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS client handshake did not unblock")
	}
}
