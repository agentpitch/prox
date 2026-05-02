package httpapi

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openai/pitchprox/internal/config"
	"github.com/openai/pitchprox/internal/history"
	"github.com/openai/pitchprox/internal/monitor"
	"github.com/openai/pitchprox/internal/proxy"
	"github.com/openai/pitchprox/internal/util"
	embedded "github.com/openai/pitchprox/internal/webui"
)

var ErrClosed = net.ErrClosed

type Runtime interface {
	CurrentConfig() config.Config
	UpdateConfig(config.Config) error
	Monitor() *monitor.Bus
	TestProxy(config.ProxyProfile, string) (proxy.ProxyTestResult, error)
}

type Server struct {
	Runtime    Runtime
	StopFunc   func()
	PauseFunc  func() error
	ResumeFunc func() error
	PausedFunc func() bool

	addr     string
	staticFS fs.FS

	mu        sync.Mutex
	listener  net.Listener
	conns     map[net.Conn]struct{}
	closeCh   chan struct{}
	closeOnce sync.Once
	closed    bool
	wg        sync.WaitGroup

	webUIMu      sync.RWMutex
	webUIEnabled bool
}

type proxyTestRequest struct {
	Proxy  config.ProxyProfile `json:"proxy"`
	Target string              `json:"target"`
}

type request struct {
	Method  string
	Path    string
	Query   url.Values
	Headers map[string]string
	Body    []byte
}

type uiVisibilityRequest struct {
	Active bool `json:"active"`
}

type droppedDeleteRequest struct {
	IDs []string `json:"ids"`
}

type droppedConnectionDTO struct {
	DropID        string            `json:"drop_id"`
	DroppedAt     time.Time         `json:"dropped_at"`
	ID            string            `json:"id"`
	PID           uint32            `json:"pid"`
	ExePath       string            `json:"exe_path"`
	SourceIP      string            `json:"source_ip"`
	SourcePort    uint16            `json:"source_port"`
	OriginalIP    string            `json:"original_ip"`
	OriginalPort  uint16            `json:"original_port"`
	Hostname      string            `json:"hostname,omitempty"`
	RuleID        string            `json:"rule_id,omitempty"`
	RuleName      string            `json:"rule_name,omitempty"`
	Action        config.RuleAction `json:"action"`
	ProxyID       string            `json:"proxy_id,omitempty"`
	ChainID       string            `json:"chain_id,omitempty"`
	State         string            `json:"state"`
	BytesUp       int64             `json:"bytes_up"`
	BytesDown     int64             `json:"bytes_down"`
	CreatedAt     time.Time         `json:"created_at"`
	LastUpdatedAt time.Time         `json:"last_updated_at"`
	Count         int64             `json:"count,omitempty"`
}

type droppedResponse struct {
	Items     []droppedConnectionDTO `json:"items"`
	Total     int                    `json:"total"`
	Offset    int                    `json:"offset"`
	Limit     int                    `json:"limit"`
	MaxBytes  int64                  `json:"max_bytes"`
	FileBytes int64                  `json:"file_bytes"`
}

func New(addr string, rt Runtime, stopFunc func()) (*Server, error) {
	sub, err := fs.Sub(embedded.FS, "dist")
	if err != nil {
		return nil, err
	}
	return &Server{
		Runtime:      rt,
		StopFunc:     stopFunc,
		addr:         addr,
		staticFS:     sub,
		conns:        map[net.Conn]struct{}{},
		closeCh:      make(chan struct{}),
		webUIEnabled: true,
	}, nil
}

func (s *Server) Start() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

func (s *Server) Listen() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.listener != nil {
		s.mu.Unlock()
		return nil
	}
	addr := s.addr
	if addr == "" {
		addr = s.Runtime.CurrentConfig().HTTP.Listen
	}
	s.mu.Unlock()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return ErrClosed
	}
	s.listener = ln
	s.mu.Unlock()
	return nil
}

func (s *Server) Serve() error {
	s.mu.Lock()
	ln := s.listener
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if ln == nil {
		return fmt.Errorf("http server listener is not initialized")
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return ErrClosed
			}
			return err
		}
		if !s.trackConn(conn) {
			continue
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer s.untrackConn(c)
			s.handleConn(c)
		}(conn)
	}
}

func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.closeCh)
		ln := s.listener
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		if ln != nil {
			err = ln.Close()
		}
	})
	s.wg.Wait()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (s *Server) trackConn(conn net.Conn) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return false
	}
	s.conns[conn] = struct{}{}
	s.mu.Unlock()
	return true
}

func (s *Server) untrackConn(conn net.Conn) {
	_ = conn.Close()
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

func (s *Server) handleConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)
	req, err := readRequest(br)
	if err != nil {
		writeText(conn, 400, err.Error())
		return
	}
	if !s.WebUIEnabled() && !isWebUIControlPath(req.Path) {
		writeText(conn, 503, "WebUI disabled")
		return
	}
	if shouldMarkUIActive(req.Path) {
		s.Runtime.Monitor().MarkUIActive()
	}
	switch req.Path {
	case "/api/health":
		s.handleHealth(conn)
	case "/api/config":
		s.handleConfig(conn, req)
	case "/api/snapshot":
		s.handleSnapshot(conn, req)
	case "/api/dropped":
		s.handleDropped(conn, req)
	case "/api/tray":
		s.handleTray(conn)
	case "/api/events":
		s.handleEvents(conn)
	case "/api/ui/visibility":
		s.handleUIVisibility(conn, req)
	case "/api/proxy-test":
		s.handleProxyTest(conn, req)
	case "/api/control/stop":
		s.handleControlStop(conn, req)
	case "/api/control/webui/status":
		s.handleWebUIStatus(conn)
	case "/api/control/webui/enable":
		s.handleWebUIEnable(conn, req)
	case "/api/control/webui/disable":
		s.handleWebUIDisable(conn, req)
	case "/api/control/service/status":
		s.handleServiceStatus(conn)
	case "/api/control/service/pause":
		s.handleServicePause(conn, req)
	case "/api/control/service/resume":
		s.handleServiceResume(conn, req)
	default:
		if strings.HasPrefix(req.Path, "/api/") {
			writeText(conn, 404, "not found")
			return
		}
		s.handleStatic(conn, req.Path)
	}
}

func (s *Server) handleHealth(conn net.Conn) {
	writeJSON(conn, 200, map[string]bool{"ok": true})
}

func (s *Server) WebUIEnabled() bool {
	s.webUIMu.RLock()
	defer s.webUIMu.RUnlock()
	return s.webUIEnabled
}

func (s *Server) SetWebUIEnabled(enabled bool) {
	s.webUIMu.Lock()
	changed := s.webUIEnabled != enabled
	s.webUIEnabled = enabled
	s.webUIMu.Unlock()
	if !enabled {
		s.Runtime.Monitor().DisableUI()
		util.ReleaseIdleMemory()
	}
	if changed {
		state := "disabled"
		if enabled {
			state = "enabled"
		}
		s.Runtime.Monitor().AddLog("info", "WebUI %s", state)
	}
}

func (s *Server) handleWebUIStatus(conn net.Conn) {
	writeJSON(conn, 200, map[string]bool{"enabled": s.WebUIEnabled(), "paused": s.ServicePaused()})
}

func (s *Server) handleWebUIEnable(conn net.Conn, req request) {
	if req.Method != "POST" {
		writeEmpty(conn, 405)
		return
	}
	if s.ServicePaused() && s.ResumeFunc != nil {
		if err := s.ResumeFunc(); err != nil {
			writeText(conn, 500, err.Error())
			return
		}
	}
	s.SetWebUIEnabled(true)
	writeJSON(conn, 200, map[string]bool{"enabled": true, "paused": s.ServicePaused()})
}

func (s *Server) handleWebUIDisable(conn net.Conn, req request) {
	if req.Method != "POST" {
		writeEmpty(conn, 405)
		return
	}
	s.SetWebUIEnabled(false)
	writeJSON(conn, 200, map[string]bool{"enabled": false})
}

func (s *Server) ServicePaused() bool {
	if s.PausedFunc == nil {
		return false
	}
	return s.PausedFunc()
}

func (s *Server) handleServiceStatus(conn net.Conn) {
	writeJSON(conn, 200, map[string]bool{
		"paused":        s.ServicePaused(),
		"webui_enabled": s.WebUIEnabled(),
	})
}

func (s *Server) handleServicePause(conn net.Conn, req request) {
	if req.Method != "POST" {
		writeEmpty(conn, 405)
		return
	}
	if s.PauseFunc == nil {
		writeText(conn, 501, "service pause is not available")
		return
	}
	if err := s.PauseFunc(); err != nil {
		writeText(conn, 500, err.Error())
		return
	}
	writeJSON(conn, 200, map[string]bool{
		"paused":        s.ServicePaused(),
		"webui_enabled": s.WebUIEnabled(),
	})
}

func (s *Server) handleServiceResume(conn net.Conn, req request) {
	if req.Method != "POST" {
		writeEmpty(conn, 405)
		return
	}
	if s.ResumeFunc == nil {
		writeText(conn, 501, "service resume is not available")
		return
	}
	if err := s.ResumeFunc(); err != nil {
		writeText(conn, 500, err.Error())
		return
	}
	writeJSON(conn, 200, map[string]bool{
		"paused":        s.ServicePaused(),
		"webui_enabled": s.WebUIEnabled(),
	})
}

func (s *Server) handleConfig(conn net.Conn, req request) {
	switch req.Method {
	case "GET":
		writeJSON(conn, 200, s.Runtime.CurrentConfig())
	case "PUT":
		var cfg config.Config
		if err := json.Unmarshal(req.Body, &cfg); err != nil {
			writeText(conn, 400, fmt.Sprintf("invalid json: %v", err))
			return
		}
		if err := s.Runtime.UpdateConfig(cfg); err != nil {
			writeText(conn, 400, err.Error())
			return
		}
		writeJSON(conn, 200, s.Runtime.CurrentConfig())
	default:
		writeEmpty(conn, 405)
	}
}

func (s *Server) handleSnapshot(conn net.Conn, req request) {
	includeLogs := true
	if req.Query.Get("include_logs") == "0" {
		includeLogs = false
	}
	writeJSON(conn, 200, s.Runtime.Monitor().SnapshotWithOptions(monitor.SnapshotOptions{IncludeLogs: includeLogs}))
}

func (s *Server) handleDropped(conn net.Conn, req request) {
	switch req.Method {
	case "GET":
		offset, err := parseNonNegativeInt(req.Query.Get("offset"), 0)
		if err != nil {
			writeText(conn, 400, "invalid offset")
			return
		}
		limit, err := parseNonNegativeInt(req.Query.Get("limit"), 100)
		if err != nil {
			writeText(conn, 400, "invalid limit")
			return
		}
		result, err := s.Runtime.Monitor().DroppedConnections(history.DroppedQuery{
			Search: req.Query.Get("q"),
			Offset: offset,
			Limit:  limit,
		})
		if err != nil {
			writeText(conn, 500, err.Error())
			return
		}
		writeJSON(conn, 200, toDroppedResponse(result))
	case "DELETE":
		var payload droppedDeleteRequest
		if len(req.Body) > 0 {
			if err := json.Unmarshal(req.Body, &payload); err != nil {
				writeText(conn, 400, fmt.Sprintf("invalid json: %v", err))
				return
			}
		}
		if len(payload.IDs) > 1000 {
			writeText(conn, 400, "too many ids")
			return
		}
		if err := s.Runtime.Monitor().DeleteDroppedConnections(payload.IDs); err != nil {
			writeText(conn, 500, err.Error())
			return
		}
		writeJSON(conn, 200, map[string]any{"deleted": len(payload.IDs)})
	default:
		writeEmpty(conn, 405)
	}
}

func parseNonNegativeInt(raw string, fallback int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid integer")
	}
	return v, nil
}

func toDroppedResponse(result history.DroppedResult) droppedResponse {
	items := make([]droppedConnectionDTO, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, toDroppedConnectionDTO(item))
	}
	return droppedResponse{
		Items:     items,
		Total:     result.Total,
		Offset:    result.Offset,
		Limit:     result.Limit,
		MaxBytes:  result.MaxBytes,
		FileBytes: result.FileBytes,
	}
}

func toDroppedConnectionDTO(item history.DroppedRecord) droppedConnectionDTO {
	c := item.Connection
	return droppedConnectionDTO{
		DropID:        item.DropID,
		DroppedAt:     item.DroppedAt,
		ID:            c.ID,
		PID:           c.PID,
		ExePath:       c.ExePath,
		SourceIP:      c.SourceIP,
		SourcePort:    c.SourcePort,
		OriginalIP:    c.OriginalIP,
		OriginalPort:  c.OriginalPort,
		Hostname:      c.Hostname,
		RuleID:        c.RuleID,
		RuleName:      c.RuleName,
		Action:        c.Action,
		ProxyID:       c.ProxyID,
		ChainID:       c.ChainID,
		State:         c.State,
		BytesUp:       c.BytesUp,
		BytesDown:     c.BytesDown,
		CreatedAt:     c.CreatedAt,
		LastUpdatedAt: c.LastUpdatedAt,
		Count:         c.Count,
	}
}

func (s *Server) handleTray(conn net.Conn) {
	writeJSON(conn, 200, s.Runtime.Monitor().TrayView(12))
}

func (s *Server) handleProxyTest(conn net.Conn, req request) {
	if req.Method != "POST" {
		writeEmpty(conn, 405)
		return
	}
	var payload proxyTestRequest
	if err := json.Unmarshal(req.Body, &payload); err != nil {
		writeText(conn, 400, fmt.Sprintf("invalid json: %v", err))
		return
	}
	result, err := s.Runtime.TestProxy(payload.Proxy, payload.Target)
	if err != nil {
		writeText(conn, 400, err.Error())
		return
	}
	writeJSON(conn, 200, result)
}

func (s *Server) handleControlStop(conn net.Conn, req request) {
	if req.Method != "POST" {
		writeEmpty(conn, 405)
		return
	}
	writeJSON(conn, 202, map[string]any{"ok": true, "stopping": true})
	if s.StopFunc != nil {
		go func() {
			time.Sleep(150 * time.Millisecond)
			s.StopFunc()
		}()
	}
}

func (s *Server) handleUIVisibility(conn net.Conn, req request) {
	if req.Method != "POST" {
		writeEmpty(conn, 405)
		return
	}
	var payload uiVisibilityRequest
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &payload); err != nil {
			writeText(conn, 400, fmt.Sprintf("invalid json: %v", err))
			return
		}
	}
	if payload.Active {
		s.Runtime.Monitor().MarkUIActive()
	} else {
		s.Runtime.Monitor().MarkUIInactive()
	}
	writeEmpty(conn, 204)
}

func (s *Server) handleEvents(conn net.Conn) {
	bw := bufio.NewWriter(conn)
	if err := writeHeaders(bw, 200, map[string]string{
		"Content-Type":  "text/event-stream",
		"Cache-Control": "no-cache",
		"Connection":    "keep-alive",
	}, -1); err != nil {
		return
	}
	_, ch, cancel := s.Runtime.Monitor().Subscribe()
	defer cancel()

	_ = conn.SetReadDeadline(time.Time{})
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			if err := writeSSE(bw, data); err != nil {
				return
			}
		case <-ticker.C:
			if _, err := bw.WriteString(": ping\n\n"); err != nil {
				return
			}
			if err := bw.Flush(); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleStatic(conn net.Conn, reqPath string) {
	name := staticAssetPath(reqPath)
	data, err := fs.ReadFile(s.staticFS, name)
	if err != nil {
		if name != "index.html" && path.Ext(name) == "" {
			data, err = fs.ReadFile(s.staticFS, "index.html")
		}
		if err != nil {
			writeText(conn, 404, "not found")
			return
		}
		name = "index.html"
	}
	writeBytes(conn, 200, contentTypeFor(name), data)
}

func readRequest(br *bufio.Reader) (request, error) {
	line, err := readLine(br)
	if err != nil {
		return request{}, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return request{}, fmt.Errorf("invalid request line")
	}
	target, err := url.ParseRequestURI(parts[1])
	if err != nil {
		return request{}, fmt.Errorf("invalid request path")
	}
	req := request{
		Method:  strings.ToUpper(strings.TrimSpace(parts[0])),
		Path:    target.Path,
		Query:   target.Query(),
		Headers: map[string]string{},
	}
	var contentLength int
	for {
		line, err := readLine(br)
		if err != nil {
			return request{}, err
		}
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return request{}, fmt.Errorf("invalid header")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		req.Headers[key] = value
		if key == "content-length" {
			contentLength, err = strconv.Atoi(value)
			if err != nil || contentLength < 0 || contentLength > 8<<20 {
				return request{}, fmt.Errorf("invalid content length")
			}
		}
		if key == "transfer-encoding" && strings.Contains(strings.ToLower(value), "chunked") {
			return request{}, fmt.Errorf("chunked requests are not supported")
		}
	}
	if contentLength > 0 {
		req.Body = make([]byte, contentLength)
		if _, err := io.ReadFull(br, req.Body); err != nil {
			return request{}, err
		}
	}
	return req, nil
}

func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func writeJSON(conn net.Conn, status int, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		writeText(conn, 500, err.Error())
		return
	}
	data = append(data, '\n')
	writeBytes(conn, status, "application/json", data)
}

func writeText(conn net.Conn, status int, message string) {
	writeBytes(conn, status, "text/plain; charset=utf-8", []byte(message+"\n"))
}

func writeEmpty(conn net.Conn, status int) {
	writeBytes(conn, status, "text/plain; charset=utf-8", nil)
}

func writeBytes(conn net.Conn, status int, contentType string, body []byte) {
	bw := bufio.NewWriter(conn)
	headers := map[string]string{
		"Content-Type":   contentType,
		"Content-Length": strconv.Itoa(len(body)),
		"Connection":     "close",
	}
	if err := writeHeaders(bw, status, headers, len(body)); err != nil {
		return
	}
	if len(body) > 0 {
		if _, err := bw.Write(body); err != nil {
			return
		}
	}
	_ = bw.Flush()
}

func writeHeaders(bw *bufio.Writer, status int, headers map[string]string, contentLength int) error {
	if _, err := fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\n", status, statusText(status)); err != nil {
		return err
	}
	for key, value := range headers {
		if value == "" {
			continue
		}
		if _, err := fmt.Fprintf(bw, "%s: %s\r\n", key, value); err != nil {
			return err
		}
	}
	if contentLength >= 0 {
		if _, err := bw.WriteString("\r\n"); err != nil {
			return err
		}
	} else {
		if _, err := bw.WriteString("\r\n"); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func writeSSE(bw *bufio.Writer, payload []byte) error {
	if _, err := bw.WriteString("data: "); err != nil {
		return err
	}
	if _, err := bw.Write(payload); err != nil {
		return err
	}
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	}
	if _, err := bw.WriteString("\n"); err != nil {
		return err
	}
	return bw.Flush()
}

func staticAssetPath(reqPath string) string {
	p := strings.TrimSpace(reqPath)
	if p == "" || p == "/" {
		return "index.html"
	}
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	p = strings.TrimPrefix(p, "/")
	if p == "" || p == "." {
		return "index.html"
	}
	return p
}

func contentTypeFor(name string) string {
	if v := mime.TypeByExtension(path.Ext(name)); v != "" {
		if strings.HasPrefix(v, "text/") && !strings.Contains(v, "charset=") {
			return v + "; charset=utf-8"
		}
		return v
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 202:
		return "Accepted"
	case 400:
		return "Bad Request"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 500:
		return "Internal Server Error"
	default:
		return "Status"
	}
}

func mustJSON(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}

func shouldMarkUIActive(path string) bool {
	if !strings.HasPrefix(path, "/api/") {
		return false
	}
	switch path {
	case "/api/health", "/api/tray", "/api/control/stop", "/api/ui/visibility", "/api/control/webui/status", "/api/control/webui/enable", "/api/control/webui/disable", "/api/control/service/status", "/api/control/service/pause", "/api/control/service/resume":
		return false
	default:
		return true
	}
}

func isWebUIControlPath(path string) bool {
	switch path {
	case "/api/health", "/api/tray", "/api/control/stop", "/api/control/webui/status", "/api/control/webui/enable", "/api/control/webui/disable", "/api/control/service/status", "/api/control/service/pause", "/api/control/service/resume":
		return true
	default:
		return false
	}
}
