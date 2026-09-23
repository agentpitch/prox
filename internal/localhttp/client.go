// Package localhttp provides bounded, single-use HTTP/1.1 requests to loopback.
// It intentionally has no TLS, proxy discovery, redirects, or request retries:
// control writes must never be repeated after an ambiguous transport failure.
package localhttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	Timeout        time.Duration
	DialTimeout    time.Duration
	MaxHeaderBytes int
	MaxBodyBytes   int
}

type Response struct {
	StatusCode int
	Header     map[string]string // Lowercase field names.
	Body       []byte
}

// Request sends exactly one request on a new connection and always closes it.
// localhost is pinned to literal loopback addresses without DNS; IPv6 fallback
// is possible only before the connection exists and no bytes have been sent.
func Request(ctx context.Context, options Options, method, rawURL string, headers map[string]string, body []byte) (Response, error) {
	var response Response
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.Fragment != "" || !token(method) {
		return response, errors.New("invalid loopback HTTP request")
	}
	host := u.Hostname()
	if !strings.EqualFold(host, "localhost") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.IsLoopback() || ip.Zone() != "" {
			return response, errors.New("non-loopback control connection rejected")
		}
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return response, errors.New("invalid loopback HTTP port")
	}
	for key, value := range headers {
		if !token(key) || !fieldValue(value) {
			return response, errors.New("invalid HTTP request header")
		}
		switch strings.ToLower(key) {
		case "host", "connection", "content-length", "transfer-encoding":
			return response, errors.New("reserved HTTP request header")
		}
	}
	if options.Timeout <= 0 || options.DialTimeout <= 0 || options.MaxHeaderBytes <= 0 || options.MaxBodyBytes <= 0 {
		return response, errors.New("positive HTTP timeout and response limits are required")
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	dialer := net.Dialer{Timeout: options.DialTimeout}
	var conn net.Conn
	if strings.EqualFold(host, "localhost") {
		conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
		if err != nil && ctx.Err() == nil {
			firstErr := err
			conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort("::1", port))
			if err != nil {
				err = errors.Join(firstErr, err)
			}
		}
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	if err != nil {
		return response, err
	}
	defer conn.Close()
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return response, err
	}
	w := bufio.NewWriter(conn)
	if _, err := fmt.Fprintf(w, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %d\r\n", method, u.RequestURI(), u.Host, len(body)); err != nil {
		return response, err
	}
	for key, value := range headers {
		if _, err := fmt.Fprintf(w, "%s: %s\r\n", key, value); err != nil {
			return response, err
		}
	}
	if _, err := w.WriteString("\r\n"); err != nil {
		return response, err
	}
	if _, err := w.Write(body); err != nil {
		return response, err
	}
	if err := w.Flush(); err != nil {
		return response, err
	}
	return readResponse(bufio.NewReader(conn), options, method)
}

func readResponse(r *bufio.Reader, options Options, method string) (Response, error) {
	var response Response
	remaining := options.MaxHeaderBytes
	for interim := 0; ; interim++ {
		line, err := readLine(r, &remaining)
		if err != nil {
			return response, err
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 || (parts[0] != "HTTP/1.1" && parts[0] != "HTTP/1.0") || len(parts[1]) != 3 {
			return response, errors.New("invalid HTTP response status")
		}
		status, err := strconv.Atoi(parts[1])
		if err != nil || status < 100 || status > 599 {
			return response, errors.New("invalid HTTP response status")
		}
		headers, err := readHeaders(r, &remaining)
		if err != nil {
			return response, err
		}
		if status >= 200 {
			response.StatusCode, response.Header = status, headers
			break
		}
		if status == 101 || interim >= 4 {
			return response, errors.New("unsupported HTTP informational response")
		}
	}
	if method == "HEAD" || response.StatusCode == 204 || response.StatusCode == 304 {
		return response, nil
	}
	lengthText, hasLength := response.Header["content-length"]
	encoding, hasEncoding := response.Header["transfer-encoding"]
	if hasEncoding {
		if hasLength || !strings.EqualFold(encoding, "chunked") {
			return response, errors.New("unsupported or ambiguous HTTP body framing")
		}
		var err error
		response.Body, err = readChunked(r, options.MaxBodyBytes, options.MaxHeaderBytes)
		return response, err
	}
	if hasLength {
		if lengthText == "" || strings.IndexFunc(lengthText, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return response, errors.New("invalid HTTP content length")
		}
		length, err := strconv.ParseUint(lengthText, 10, 63)
		if err != nil || length > uint64(options.MaxBodyBytes) {
			return response, errors.New("HTTP response exceeds body limit")
		}
		response.Body = make([]byte, int(length))
		_, err = io.ReadFull(r, response.Body)
		return response, err
	}
	var err error
	response.Body, err = io.ReadAll(io.LimitReader(r, int64(options.MaxBodyBytes)+1))
	if len(response.Body) > options.MaxBodyBytes {
		return response, errors.New("HTTP response exceeds body limit")
	}
	return response, err
}

func readLine(r *bufio.Reader, remaining *int) (string, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(part) > *remaining {
			return "", errors.New("HTTP response exceeds header limit")
		}
		*remaining -= len(part)
		line = append(line, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return "", err
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return "", errors.New("invalid HTTP line ending")
		}
		return string(line[:len(line)-2]), nil
	}
}

func readHeaders(r *bufio.Reader, remaining *int) (map[string]string, error) {
	headers := make(map[string]string)
	for {
		line, err := readLine(r, remaining)
		if err != nil {
			return nil, err
		}
		if line == "" {
			return headers, nil
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || !token(key) || !fieldValue(value) {
			return nil, errors.New("invalid HTTP response header")
		}
		key, value = strings.ToLower(key), strings.TrimSpace(value)
		if previous, exists := headers[key]; exists {
			if key == "content-length" || key == "transfer-encoding" {
				return nil, errors.New("duplicate HTTP framing header")
			}
			value = previous + ", " + value
		}
		headers[key] = value
	}
}

func readChunked(r *bufio.Reader, maxBody, maxHeaders int) ([]byte, error) {
	var body bytes.Buffer
	// A separate total bound also prevents unlimited chunk extensions/trailers.
	remaining := maxHeaders
	for {
		line, err := readLine(r, &remaining)
		if err != nil {
			return nil, err
		}
		sizeText, _, _ := strings.Cut(line, ";")
		size, err := strconv.ParseUint(sizeText, 16, 63)
		if err != nil || size > uint64(maxBody-body.Len()) {
			return nil, errors.New("invalid chunk size or HTTP response exceeds body limit")
		}
		if size == 0 {
			_, err := readHeaders(r, &remaining)
			return body.Bytes(), err
		}
		if _, err := io.CopyN(&body, r, int64(size)); err != nil {
			return nil, err
		}
		var ending [2]byte
		if _, err := io.ReadFull(r, ending[:]); err != nil {
			return nil, err
		}
		if ending != [2]byte{'\r', '\n'} {
			return nil, errors.New("invalid HTTP chunk ending")
		}
	}
}

func token(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if c <= 32 || c >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(c)) {
			return false
		}
	}
	return true
}

func fieldValue(value string) bool {
	for i := range len(value) {
		if (value[i] < 32 && value[i] != '\t') || value[i] == 127 {
			return false
		}
	}
	return true
}
