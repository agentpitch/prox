//go:build !windows

package httpclient

import (
	"context"
	"net/http"
)

func roundTrip(ctx context.Context, request *Request) (*Response, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, request.URL.String(), nil)
	if err != nil {
		return nil, err
	}
	for name, value := range request.Header {
		r.Header.Set(name, value)
	}
	// Redirect policy belongs to Client.Do, including the host allowlist.
	client := http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	headers := make(Header, len(response.Header))
	for name := range response.Header {
		headers.Set(name, response.Header.Get(name))
	}
	return &Response{StatusCode: response.StatusCode, ContentLength: response.ContentLength, Header: headers, Body: response.Body}, nil
}
