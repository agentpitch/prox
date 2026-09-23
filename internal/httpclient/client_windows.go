//go:build windows

package httpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	flagAsync                 = 0x10000000
	flagSecure                = 0x00800000
	accessNoProxy             = 1
	accessNamedProxy          = 3
	optionDisableFeature      = 63
	optionSecureProtocols     = 84
	optionContextValue        = 45
	optionMaxResponseHeader   = 91
	disableCookies            = 1
	disableRedirects          = 2
	disableAuthentication     = 4
	disableKeepAlive          = 8
	statusHandleClosing       = 0x00000800
	statusHeadersAvailable    = 0x00020000
	statusReadComplete        = 0x00080000
	statusRequestError        = 0x00200000
	statusSendRequestComplete = 0x00400000
	queryRawHeadersCRLF       = 22
	maxResponseHeaderBytes    = 64 << 10
)

var (
	winHTTP              = windows.NewLazySystemDLL("winhttp.dll")
	winOpen              = winHTTP.NewProc("WinHttpOpen")
	winConnect           = winHTTP.NewProc("WinHttpConnect")
	winOpenRequest       = winHTTP.NewProc("WinHttpOpenRequest")
	winSetOption         = winHTTP.NewProc("WinHttpSetOption")
	winSetTimeouts       = winHTTP.NewProc("WinHttpSetTimeouts")
	winSetStatusCallback = winHTTP.NewProc("WinHttpSetStatusCallback")
	winSendRequest       = winHTTP.NewProc("WinHttpSendRequest")
	winReceiveResponse   = winHTTP.NewProc("WinHttpReceiveResponse")
	winQueryHeaders      = winHTTP.NewProc("WinHttpQueryHeaders")
	winReadData          = winHTTP.NewProc("WinHttpReadData")
	winCloseHandle       = winHTTP.NewProc("WinHttpCloseHandle")
	callbackAddress      = syscall.NewCallback(requestCallback)
	requestSequence      atomic.Uintptr
	requests             sync.Map // uintptr token -> *nativeRequest; removed by final callback
)

type nativeEvent struct {
	status uint32
	length uint32
	err    error
}

type nativeRequest struct {
	ctx        context.Context
	callMu     sync.Mutex // an API invocation cannot race handle close
	readMu     sync.Mutex // only one outstanding native operation
	closeOnce  sync.Once
	handle     uintptr
	connection uintptr
	session    uintptr
	events     chan nativeEvent
	closed     chan struct{}
	remaining  int64 // protected by readMu after response headers
}

// The only value retained by Windows is an integer token, never a Go pointer.
// Read buffers are pinned until completion or the final HANDLE_CLOSING event.
func requestCallback(_ uintptr, token uintptr, status uint32, information unsafe.Pointer, length uint32) uintptr {
	value, ok := requests.Load(token)
	if !ok {
		return 0
	}
	request := value.(*nativeRequest)
	if status == statusHandleClosing {
		requests.Delete(token)
		close(request.closed)
		return 0
	}
	event := nativeEvent{status: status, length: length}
	if status == statusRequestError {
		result := (*struct {
			Operation uintptr
			Error     uint32
		})(information)
		event.err = syscall.Errno(result.Error)
	}
	// One async operation is in flight; the queue also accommodates its error
	// while Close is cancelling it. A callback must never wait on the caller.
	select {
	case request.events <- event:
	default:
	}
	return 0
}

func roundTrip(ctx context.Context, request *Request) (_ *Response, returnErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proxy, err := proxyForURL(request.URL)
	if err != nil {
		return nil, err
	}
	access := uintptr(accessNoProxy)
	var proxyName *uint16
	if proxy != "" {
		access = accessNamedProxy
		proxyName, err = windows.UTF16PtrFromString(proxy)
		if err != nil {
			return nil, errors.New("invalid proxy address")
		}
	}
	userAgent, _ := windows.UTF16PtrFromString("pitchProx-updater")
	session, _, callErr := winOpen.Call(uintptr(unsafe.Pointer(userAgent)), access, uintptr(unsafe.Pointer(proxyName)), 0, flagAsync)
	if session == 0 {
		return nil, nativeError("open session", callErr)
	}
	var connection, handle uintptr
	owned := true
	defer func() {
		if owned {
			closeNative(handle)
			closeNative(connection)
			closeNative(session)
		}
	}()
	// Explicit minimum TLS 1.2, with TLS 1.3 where the OS supports it. Never
	// enable certificate-error exceptions or legacy TLS fallback.
	if err := setDWORD(session, optionSecureProtocols, 0x800|0x2000); err != nil {
		if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil, err
		}
		if err := setDWORD(session, optionSecureProtocols, 0x800); err != nil {
			return nil, err
		}
	}
	if result, _, err := winSetTimeouts.Call(session, 30000, 30000, 30000, 30000); result == 0 {
		return nil, nativeError("set timeouts", err)
	}
	port := uint64(80)
	if request.URL.Scheme == "https" {
		port = 443
	}
	if explicit := request.URL.Port(); explicit != "" {
		var err error
		port, err = strconv.ParseUint(explicit, 10, 16)
		if err != nil || port == 0 {
			return nil, errors.New("invalid HTTP port")
		}
	}
	host, err := windows.UTF16PtrFromString(request.URL.Hostname())
	if err != nil {
		return nil, err
	}
	connection, _, callErr = winConnect.Call(session, uintptr(unsafe.Pointer(host)), uintptr(port), 0)
	if connection == 0 {
		return nil, nativeError("connect", callErr)
	}
	verb, _ := windows.UTF16PtrFromString("GET")
	path, err := windows.UTF16PtrFromString(request.URL.RequestURI())
	if err != nil {
		return nil, err
	}
	var flags uintptr
	if request.URL.Scheme == "https" {
		flags = flagSecure
	}
	handle, _, callErr = winOpenRequest.Call(connection, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(path)), 0, 0, 0, flags)
	if handle == 0 {
		return nil, nativeError("open request", callErr)
	}
	// A manual update must not leave WinHTTP's cross-session idle connection
	// pool alive after all application-owned handles have been released.
	if err := setDWORD(handle, optionDisableFeature, disableCookies|disableRedirects|disableAuthentication|disableKeepAlive); err != nil {
		return nil, err
	}
	if err := setDWORD(handle, optionMaxResponseHeader, maxResponseHeaderBytes); err != nil {
		return nil, err
	}
	headers, err := encodeHeaders(request.Header)
	if err != nil {
		return nil, err
	}
	var headerPin runtime.Pinner
	headerPin.Pin(&headers[0])
	defer headerPin.Unpin()
	token := requestSequence.Add(1)
	state := &nativeRequest{ctx: ctx, handle: handle, connection: connection, session: session, events: make(chan nativeEvent, 4), closed: make(chan struct{})}
	if result, _, err := winSetOption.Call(handle, optionContextValue, uintptr(unsafe.Pointer(&token)), unsafe.Sizeof(token)); result == 0 {
		return nil, nativeError("set request context", err)
	}
	requests.Store(token, state)
	callbackFlags := uintptr(statusHandleClosing | statusHeadersAvailable | statusReadComplete | statusRequestError | statusSendRequestComplete)
	if result, _, err := winSetStatusCallback.Call(handle, callbackAddress, callbackFlags, 0); result == ^uintptr(0) {
		requests.Delete(token)
		return nil, nativeError("set request callback", err)
	}
	owned = false
	stopCancel := context.AfterFunc(ctx, func() { _ = state.Close() })
	defer func() {
		if returnErr != nil {
			stopCancel()
			_ = state.Close()
		}
	}()
	if err := state.call(winSendRequest, uintptr(unsafe.Pointer(&headers[0])), uintptr(len(headers)-1), 0, 0, 0, token); err != nil {
		return nil, err
	}
	if _, err := state.wait(statusSendRequestComplete); err != nil {
		return nil, err
	}
	runtime.KeepAlive(headers)
	if err := state.call(winReceiveResponse, 0); err != nil {
		return nil, err
	}
	if _, err := state.wait(statusHeadersAvailable); err != nil {
		return nil, err
	}
	response, err := state.response()
	if err != nil {
		return nil, err
	}
	response.Body = &nativeBody{nativeRequest: state, stopCancel: stopCancel}
	state.remaining = response.ContentLength
	return response, nil
}

func encodeHeaders(headers Header) ([]uint16, error) {
	var value strings.Builder
	for name, entry := range headers {
		if name == "" || strings.ContainsAny(name, "\r\n:\x00 ") || strings.ContainsAny(entry, "\r\n\x00") {
			return nil, errors.New("invalid HTTP header")
		}
		value.WriteString(name)
		value.WriteString(": ")
		value.WriteString(entry)
		value.WriteString("\r\n")
	}
	return windows.UTF16FromString(value.String())
}

func setDWORD(handle uintptr, option uintptr, value uint32) error {
	if result, _, err := winSetOption.Call(handle, option, uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value)); result == 0 {
		return nativeError("set option", err)
	}
	return nil
}

func nativeError(operation string, err error) error {
	if err == nil || err == syscall.Errno(0) {
		err = syscall.EINVAL
	}
	return fmt.Errorf("WinHTTP %s: %w", operation, err)
}

func closeNative(handle uintptr) {
	if handle != 0 {
		_, _, _ = winCloseHandle.Call(handle)
	}
}

func (r *nativeRequest) call(procedure *windows.LazyProc, arguments ...uintptr) error {
	r.callMu.Lock()
	defer r.callMu.Unlock()
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if r.handle == 0 {
		return errors.New("HTTP response is closed")
	}
	result, _, err := procedure.Call(append([]uintptr{r.handle}, arguments...)...)
	if result == 0 {
		return nativeError(procedure.Name, err)
	}
	return nil
}

func (r *nativeRequest) wait(wanted uint32) (nativeEvent, error) {
	select {
	case event := <-r.events:
		if err := r.ctx.Err(); err != nil {
			_ = r.Close()
			return nativeEvent{}, err
		}
		if event.err != nil {
			return nativeEvent{}, nativeError("request", event.err)
		}
		if event.status != wanted {
			return nativeEvent{}, errors.New("unexpected WinHTTP completion")
		}
		return event, nil
	case <-r.ctx.Done():
		_ = r.Close()
		return nativeEvent{}, r.ctx.Err()
	case <-r.closed:
		return nativeEvent{}, errors.New("HTTP response is closed")
	}
}

func (r *nativeRequest) response() (*Response, error) {
	r.callMu.Lock()
	defer r.callMu.Unlock()
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if r.handle == 0 {
		return nil, errors.New("HTTP response is closed")
	}
	var size uint32
	result, _, callErr := winQueryHeaders.Call(r.handle, queryRawHeadersCRLF, 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if result == 0 && !errors.Is(callErr, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, nativeError("query headers", callErr)
	}
	if size == 0 || size > maxResponseHeaderBytes {
		return nil, errors.New("HTTP response headers exceed limit")
	}
	buffer := make([]uint16, (size+1)/2)
	if result, _, err := winQueryHeaders.Call(r.handle, queryRawHeadersCRLF, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0); result == 0 {
		return nil, nativeError("read headers", err)
	}
	lines := strings.Split(windows.UTF16ToString(buffer), "\r\n")
	status := strings.Fields(lines[0])
	if len(status) < 2 {
		return nil, errors.New("invalid HTTP status line")
	}
	code, err := strconv.Atoi(status[1])
	if err != nil || code < 100 || code > 599 {
		return nil, errors.New("invalid HTTP status code")
	}
	headers := make(Header)
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return nil, errors.New("invalid HTTP response header")
		}
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if previous, exists := headers[name]; exists {
			value = previous + ", " + value
		}
		headers.Set(name, value)
	}
	length := int64(-1)
	if value := headers.Get("Content-Length"); value != "" {
		length, err = strconv.ParseInt(value, 10, 64)
		if err != nil || length < 0 {
			return nil, errors.New("invalid HTTP content length")
		}
	}
	return &Response{StatusCode: code, ContentLength: length, Header: headers}, nil
}

type nativeBody struct {
	*nativeRequest
	stopCancel func() bool
}

func (b *nativeBody) Close() error {
	b.stopCancel()
	return b.nativeRequest.Close()
}

func (r *nativeRequest) Read(buffer []byte) (int, error) {
	r.readMu.Lock()
	defer r.readMu.Unlock()
	if len(buffer) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if len(buffer) > 64<<10 {
		buffer = buffer[:64<<10]
	}
	var pinned runtime.Pinner
	pinned.Pin(&buffer[0])
	defer pinned.Unpin()
	if err := r.call(winReadData, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0); err != nil {
		return 0, err
	}
	event, err := r.wait(statusReadComplete)
	if err != nil {
		// A failed/cancelled read may still have a native reference to buffer.
		_ = r.Close()
		return 0, err
	}
	if event.length == 0 {
		if r.remaining > 0 {
			return 0, io.ErrUnexpectedEOF
		}
		return 0, io.EOF
	}
	if uint64(event.length) > uint64(len(buffer)) {
		return 0, errors.New("invalid WinHTTP read length")
	}
	if r.remaining >= 0 {
		r.remaining -= int64(event.length)
		if r.remaining < 0 {
			return 0, errors.New("HTTP response exceeds declared content length")
		}
	}
	return int(event.length), nil
}

func (r *nativeRequest) Close() error {
	r.closeOnce.Do(func() {
		r.callMu.Lock()
		handle := r.handle
		r.handle = 0
		closeNative(handle)
		r.callMu.Unlock()
		// HANDLE_CLOSING is the final callback. Only now can async buffers and
		// their Go state be released; closing a synchronous request instead
		// would race the native call (see Microsoft's WinHTTP concurrency API).
		<-r.closed
		closeNative(r.connection)
		closeNative(r.session)
	})
	return nil
}
