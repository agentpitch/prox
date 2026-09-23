package proxy

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

type sniffReaderConn struct {
	trackedConnStub
	reader io.Reader
}

func (c *sniffReaderConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func TestPeekAndSniffHTTPPreservesBufferedAndFragmentedRequests(t *testing.T) {
	for _, tc := range []struct{ name, request, hostname string }{
		{"mixed-case Host", "GET / HTTP/1.1\r\nX-Pad: " + strings.Repeat("x", 3000) + "\r\nhOsT: Example.COM:80\r\n\r\npayload", "example.com"},
		{"CONNECT", "CONNECT Example.COM:443 HTTP/1.1\r\n\r\npayload", "example.com"},
		{"Host in body is not a header", "POST / HTTP/1.1\r\nContent-Length: 19\r\n\r\nHost: fake.example\r\n", ""},
	} {
		for _, fragmented := range []bool{false, true} {
			name := tc.name + "/buffered"
			var input io.Reader = strings.NewReader(tc.request)
			if fragmented {
				name = tc.name + "/fragmented"
				input = iotest.OneByteReader(input)
			}
			t.Run(name, func(t *testing.T) {
				conn := &sniffReaderConn{reader: input}
				br, result, err := PeekAndSniff(conn, 4096, 0)
				if err != nil || result.Hostname != tc.hostname {
					t.Fatalf("sniff result=%+v error=%v, want %q", result, err, tc.hostname)
				}
				data, err := io.ReadAll(br)
				if err != nil || string(data) != tc.request {
					t.Fatalf("sniff consumed/changed request: error=%v len=%d want=%d", err, len(data), len(tc.request))
				}
			})
		}
	}
}

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

func TestSniffTLSSNISpansRecords(t *testing.T) {
	hello := testClientHello("Example.COM")
	payload := hello[5:]
	split := len(payload) / 2
	data := appendTLSRecord(nil, payload[:split])
	data = appendTLSRecord(data, payload[split:])
	if got := normalizeSniffedHostname(sniffTLSSNI(data)); got != "example.com" {
		t.Fatalf("sniffTLSSNI = %q, want example.com", got)
	}
	if need, ok := tlsRecordNeed(data[:len(data)-3]); !ok || need != len(data) {
		t.Fatalf("tlsRecordNeed = (%d, %v), want (%d, true)", need, ok, len(data))
	}
}

func TestSniffTLSRejectsUnsafeServerName(t *testing.T) {
	hello := testClientHello("safe.example\r\nInjected: yes")
	if raw := sniffTLSSNI(hello); raw == "" {
		t.Fatal("test ClientHello did not contain an SNI value")
	} else if got := normalizeSniffedHostname(raw); got != "" {
		t.Fatalf("unsafe SNI normalized to %q", got)
	}
}

func testClientHello(host string) []byte {
	name := []byte(host)
	sniListLen := 1 + 2 + len(name)
	sniDataLen := 2 + sniListLen
	extensionsLen := 4 + sniDataLen
	bodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensionsLen
	handshake := make([]byte, 4+bodyLen)
	handshake[0] = 0x01
	handshake[1] = byte(bodyLen >> 16)
	handshake[2] = byte(bodyLen >> 8)
	handshake[3] = byte(bodyLen)
	p := handshake[4:]
	p[0], p[1] = 0x03, 0x03
	p = p[2+32:]
	p[0] = 0
	p = p[1:]
	binary.BigEndian.PutUint16(p[:2], 2)
	p[2], p[3] = 0x13, 0x01
	p = p[4:]
	p[0], p[1] = 1, 0
	p = p[2:]
	binary.BigEndian.PutUint16(p[:2], uint16(extensionsLen))
	p = p[2:]
	p[0], p[1] = 0, 0
	binary.BigEndian.PutUint16(p[2:4], uint16(sniDataLen))
	binary.BigEndian.PutUint16(p[4:6], uint16(sniListLen))
	p[6] = 0
	binary.BigEndian.PutUint16(p[7:9], uint16(len(name)))
	copy(p[9:], name)
	return appendTLSRecord(nil, handshake)
}

func appendTLSRecord(dst, payload []byte) []byte {
	dst = append(dst, 0x16, 0x03, 0x01, byte(len(payload)>>8), byte(len(payload)))
	return append(dst, payload...)
}
