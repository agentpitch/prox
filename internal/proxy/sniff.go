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
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
	peek, err := peekSniffData(br, maxBytes)
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Time{})
	}
	if err != nil {
		return br, SniffResult{}, err
	}
	if host := normalizeSniffedHostname(sniffHTTPHost(peek)); host != "" {
		return br, SniffResult{Hostname: host, Protocol: "http"}, nil
	}
	if host := normalizeSniffedHostname(sniffTLSSNI(peek)); host != "" {
		return br, SniffResult{Hostname: host, Protocol: "tls"}, nil
	}
	return br, SniffResult{}, nil
}

func peekSniffData(br *bufio.Reader, maxBytes int) ([]byte, error) {
	target := min(maxBytes, 5)
	for {
		peek, err := br.Peek(target)
		if err != nil {
			if len(peek) > 0 || errors.Is(err, bufio.ErrBufferFull) || errors.Is(err, io.EOF) || isTimeout(err) {
				return peek, nil
			}
			return peek, err
		}
		// Peek may have filled the reader with a complete request. Parse those
		// available bytes together instead of reparsing the same header for each
		// additional byte (quadratic CPU and allocation cost for long headers).
		if available := min(maxBytes, br.Buffered()); available > len(peek) {
			peek, _ = br.Peek(available)
		}
		if sniffHTTPHost(peek) != "" {
			return peek, nil
		}
		if need, ok := tlsRecordNeed(peek); ok {
			next := min(maxBytes, need)
			if len(peek) >= next || next <= target {
				return peek, nil
			}
			target = next
			continue
		}
		if looksLikeHTTPRequest(peek) {
			if bytes.Contains(peek, []byte("\r\n\r\n")) || len(peek) >= maxBytes {
				return peek, nil
			}
			target = min(maxBytes, len(peek)+1)
			continue
		}
		if couldBecomeHTTPMethod(peek) && len(peek) < maxHTTPMethodLen && len(peek) < maxBytes {
			target = min(maxBytes, len(peek)+1)
			continue
		}
		return peek, nil
	}
}

var httpMethodPrefixes = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("HEAD "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("CONNECT "),
}

const maxHTTPMethodLen = len("OPTIONS ")

func sniffHTTPHost(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	ok := false
	for _, m := range httpMethodPrefixes {
		if bytes.HasPrefix(data, m) {
			ok = true
			break
		}
	}
	if !ok {
		return ""
	}
	for len(data) > 0 {
		line, rest, completeLine := bytes.Cut(data, []byte("\r\n"))
		if !completeLine || len(line) == 0 {
			return ""
		}
		data = rest
		if len(line) >= 5 && bytes.EqualFold(line[:5], []byte("host:")) {
			host := strings.TrimSpace(string(line[5:]))
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			return strings.ToLower(strings.Trim(host, "[]"))
		}
		if len(line) >= 8 && bytes.EqualFold(line[:8], []byte("connect ")) {
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

func looksLikeHTTPRequest(data []byte) bool {
	for _, method := range httpMethodPrefixes {
		if bytes.HasPrefix(data, method) {
			return true
		}
	}
	return false
}

func couldBecomeHTTPMethod(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	upper := bytes.ToUpper(data)
	for _, method := range httpMethodPrefixes {
		if len(upper) <= len(method) && bytes.HasPrefix(method, upper) {
			return true
		}
	}
	return false
}

func tlsRecordNeed(data []byte) (int, bool) {
	if len(data) == 0 || data[0] != 0x16 {
		return 0, false
	}
	offset := 0
	payloadBytes := 0
	handshakeNeed := -1
	var handshakeHeader [4]byte
	headerBytes := 0
	for records := 0; records < 8; records++ {
		if len(data) < offset+5 {
			return offset + 5, true
		}
		if data[offset] != 0x16 {
			return len(data), true
		}
		recLen := int(data[offset+3])<<8 | int(data[offset+4])
		if recLen <= 0 {
			return offset + 5, true
		}
		end := offset + 5 + recLen
		if len(data) < end {
			return end, true
		}
		payload := data[offset+5 : end]
		if headerBytes < len(handshakeHeader) {
			n := copy(handshakeHeader[headerBytes:], payload)
			headerBytes += n
			if headerBytes == len(handshakeHeader) {
				if handshakeHeader[0] != 0x01 {
					return end, true
				}
				handshakeNeed = 4 + int(handshakeHeader[1])<<16 + int(handshakeHeader[2])<<8 + int(handshakeHeader[3])
			}
		}
		payloadBytes += len(payload)
		if handshakeNeed >= 0 && payloadBytes >= handshakeNeed {
			return end, true
		}
		offset = end
	}
	return offset, true
}

func sniffTLSSNI(data []byte) string {
	payload, ok := tlsClientHelloPayload(data)
	if !ok {
		return ""
	}
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
					return string(p2[:nameLen])
				}
				p2 = p2[nameLen:]
			}
			return ""
		}
		exts = exts[l:]
	}
	return ""
}

func tlsClientHelloPayload(data []byte) ([]byte, bool) {
	if len(data) < 5 || data[0] != 0x16 {
		return nil, false
	}
	var joined []byte
	offset := 0
	for records := 0; records < 8; records++ {
		if len(data) < offset+5 || data[offset] != 0x16 {
			return nil, false
		}
		recLen := int(data[offset+3])<<8 | int(data[offset+4])
		end := offset + 5 + recLen
		if recLen <= 0 || len(data) < end {
			return nil, false
		}
		payload := data[offset+5 : end]
		if joined == nil && len(payload) >= 4 {
			need := 4 + int(payload[1])<<16 + int(payload[2])<<8 + int(payload[3])
			if payload[0] == 0x01 && len(payload) >= need {
				return payload[:need], true
			}
		}
		joined = append(joined, payload...)
		if len(joined) >= 4 {
			need := 4 + int(joined[1])<<16 + int(joined[2])<<8 + int(joined[3])
			if joined[0] != 0x01 {
				return nil, false
			}
			if len(joined) >= need {
				return joined[:need], true
			}
		}
		offset = end
	}
	return nil, false
}

func normalizeSniffedHostname(host string) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return strings.ToLower(host)
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return ""
		}
	}
	return strings.ToLower(host)
}

func isTimeout(err error) bool {
	type timeout interface{ Timeout() bool }
	var te timeout
	return errors.As(err, &te) && te.Timeout()
}
