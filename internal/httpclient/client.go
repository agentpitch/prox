// Package httpclient provides the updater's small, streaming GET transport.
// Windows uses the operating system TLS implementation instead of retaining a
// second TLS stack in the background application.
package httpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

type Header map[string]string

func (h Header) Set(name, value string) { h[strings.ToLower(name)] = value }
func (h Header) Get(name string) string { return h[strings.ToLower(name)] }

type Request struct {
	URL    *url.URL
	Header Header
}

type Response struct {
	StatusCode    int
	ContentLength int64
	Header        Header
	Body          io.ReadCloser
}

type Client struct {
	// Timeout covers redirects, response headers and reading the body.
	Timeout time.Duration
	// CheckRedirect must authorize each redirect before any connection to it.
	// A nil callback returns redirects to the caller without following them.
	CheckRedirect func(destination *url.URL, redirects int) error
}

func (c *Client) Do(ctx context.Context, request *Request) (*Response, error) {
	if request == nil || request.URL == nil {
		return nil, errors.New("missing HTTP request URL")
	}
	var cancel context.CancelFunc
	if c.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Do not let response-body lifetime cancel the caller's context.
	keep := false
	defer func() {
		if !keep {
			cancel()
		}
	}()
	current := *request.URL
	for redirects := 0; ; redirects++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if current.User != nil || current.Hostname() == "" || (current.Scheme != "https" && current.Scheme != "http") {
			return nil, errors.New("invalid HTTP request URL")
		}
		response, err := roundTrip(ctx, &Request{URL: &current, Header: request.Header})
		if err != nil {
			return nil, err
		}
		location := response.Header.Get("Location")
		if !isRedirect(response.StatusCode) || location == "" || c.CheckRedirect == nil {
			response.Body = &cancelBody{ReadCloser: response.Body, cancel: cancel}
			keep = true
			return response, nil
		}
		_ = response.Body.Close()
		if redirects >= 9 {
			return nil, errors.New("too many HTTP redirects")
		}
		next, err := redirectDestination(&current, location)
		if err != nil {
			return nil, err
		}
		if err := c.CheckRedirect(next, redirects+1); err != nil {
			return nil, err
		}
		current = *next
	}
}

func redirectDestination(current *url.URL, location string) (*url.URL, error) {
	next, err := current.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse HTTP redirect: %w", err)
	}
	if current.Scheme == "https" && next.Scheme != "https" {
		return nil, errors.New("HTTP redirect must not downgrade HTTPS")
	}
	return next, nil
}

func isRedirect(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}
