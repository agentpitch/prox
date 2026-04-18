package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

type SniffResult struct {
	Hostname string `json:"hostname,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

func PeekAndSniff(conn net.Conn, maxBytes int, timeout time.Duration) (*bufio.Reader, SniffResult, error) {
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	br := bufio.NewReaderSize(conn, maxBytes)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	peek, err := br.Peek(maxBytes)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) && !isTimeout(err) {
		return br, SniffResult{}, err
	}
	peek = bytes.TrimSpace(peek)
	if host := sniffHTTPHost(peek); host != "" {
		return br, SniffResult{Hostname: host, Protocol: "http"}, nil
	}
	if host := sniffTLSSNI(peek); host != "" {
		return br, SniffResult{Hostname: host, Protocol: "tls"}, nil
	}
	return br, SniffResult{}, nil
}

func sniffHTTPHost(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	methods := [][]byte{[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT ")}
	ok := false
	for _, m := range methods {
		if bytes.HasPrefix(data, m) {
			ok = true
			break
		}
	}
	if !ok {
		return ""
	}
	for _, line := range bytes.Split(data, []byte("\r\n")) {
		lower := strings.ToLower(string(line))
		if strings.HasPrefix(lower, "host:") {
			host := strings.TrimSpace(string(line[5:]))
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			return strings.ToLower(strings.Trim(host, "[]"))
		}
		if strings.HasPrefix(lower, "connect ") {
			parts := strings.SplitN(string(line), " ", 3)
			if len(parts) >= 2 {
				host := parts[1]
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				return strings.ToLower(strings.Trim(host, "[]"))
			}
		}
	}
	return ""
}

func sniffTLSSNI(data []byte) string {
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	recLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recLen || recLen < 42 {
		return ""
	}
	payload := data[5 : 5+recLen]
	if payload[0] != 0x01 || len(payload) < 4 {
		return ""
	}
	bodyLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+bodyLen {
		return ""
	}
	p := payload[4:]
	if len(p) < 2+32+1 {
		return ""
	}
	p = p[2+32:]
	sidLen := int(p[0])
	if len(p) < 1+sidLen+2 {
		return ""
	}
	p = p[1+sidLen:]
	csLen := int(p[0])<<8 | int(p[1])
	if len(p) < 2+csLen+1 {
		return ""
	}
	p = p[2+csLen:]
	compLen := int(p[0])
	if len(p) < 1+compLen+2 {
		return ""
	}
	p = p[1+compLen:]
	extLen := int(p[0])<<8 | int(p[1])
	if len(p) < 2+extLen {
		return ""
	}
	exts := p[2 : 2+extLen]
	for len(exts) >= 4 {
		typ := int(exts[0])<<8 | int(exts[1])
		l := int(exts[2])<<8 | int(exts[3])
		exts = exts[4:]
		if len(exts) < l {
			return ""
		}
		if typ == 0 {
			sni := exts[:l]
			if len(sni) < 2 {
				return ""
			}
			listLen := int(sni[0])<<8 | int(sni[1])
			if len(sni) < 2+listLen {
				return ""
			}
			p2 := sni[2 : 2+listLen]
			for len(p2) >= 3 {
				nameType := p2[0]
				nameLen := int(p2[1])<<8 | int(p2[2])
				p2 = p2[3:]
				if len(p2) < nameLen {
					return ""
				}
				if nameType == 0 {
					return strings.ToLower(string(p2[:nameLen]))
				}
				p2 = p2[nameLen:]
			}
			return ""
		}
		exts = exts[l:]
	}
	return ""
}

func isTimeout(err error) bool {
	type timeout interface{ Timeout() bool }
	var te timeout
	return errors.As(err, &te) && te.Timeout()
}
