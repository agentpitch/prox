package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agentpitch/prox/internal/buildinfo"
	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/history"
	"github.com/agentpitch/prox/internal/monitor"
	"github.com/agentpitch/prox/internal/proxy"
	"github.com/agentpitch/prox/internal/updater"
	"github.com/agentpitch/prox/internal/util"
	embedded "github.com/agentpitch/prox/internal/webui"
)

var (
	ErrClosed                    = net.ErrClosed
	errUpdateInstallBodyTooLarge = errors.New("update install request body is too large")
)

type Runtime interface {
	CurrentConfig() config.Config
	UpdateConfigIfCurrent(config.Config, time.Time) error
	Monitor() *monitor.Bus
	TestProxy(config.ProxyProfile, string) (proxy.ProxyTestResult, error)
}

type Updater interface {
	Check(context.Context) (updater.CheckResult, error)
	StartInstall(string) (updater.Status, error)
	Status() updater.Status
	HealthToken() string
}

type Server struct {
	Runtime    Runtime
	Updater    Updater
	StopFunc   func()
	PauseFunc  func() error
	ResumeFunc func() error
	PausedFunc func() bool

	addr     string
	staticFS fs.FS

	mu        sync.Mutex
	listener  net.Listener
	conns     map[net.Conn]struct{}
	connPeak  int
	closeCh   chan struct{}
	closeOnce sync.Once
	closed    bool
	wg        sync.WaitGroup

	webUITransitionMu       sync.Mutex
	webUIMu                 sync.RWMutex
	webUIEnabled            bool
	webUIDisabledReason     string
	webUIDisabledAt         time.Time
	webUILastBrowserRequest time.Time
	webUIIdleTimeout        time.Duration
	webUIIdleTimer          *time.Timer
	webUIIdleGeneration     uint64
	webUIIdleClosed         bool
	webUIIdleWG             sync.WaitGroup
	webUIIdleCallbackHook   func() func()
	updaterMu               sync.RWMutex
	updateMutationMu        sync.Mutex
	shutdownCtx             context.Context
	shutdownCancel          context.CancelFunc
}

func (s *Server) SetUpdater(service Updater) {
	s.updaterMu.Lock()
	s.Updater = service
	s.updaterMu.Unlock()
}

func (s *Server) updater() Updater {
	s.updaterMu.RLock()
	defer s.updaterMu.RUnlock()
	return s.Updater
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

type webUIStatusDTO struct {
	Enabled            bool       `json:"enabled"`
	Paused             bool       `json:"paused"`
	AutoPaused         bool       `json:"auto_paused"`
	DisabledReason     string     `json:"disabled_reason,omitempty"`
	DisabledAt         *time.Time `json:"disabled_at,omitempty"`
	IdleTimeoutSeconds int64      `json:"idle_timeout_seconds"`
	IdleDeadlineAt     *time.Time `json:"idle_deadline_at,omitempty"`
}

type droppedDeleteRequest struct {
	IDs []string `json:"ids"`
}

type updateInstallRequest struct {
	Version string `json:"version"`
}

const (
	maxHTTPConnections        = 64
	maxHTTPHeaders            = 100
	maxHTTPHeaderBytes        = 32 << 10
	maxUpdateInstallBodyBytes = 512
	maxUpdateVersionBytes     = 128
	httpWriteTimeout          = 10 * time.Second
	httpRejectWriteTimeout    = 100 * time.Millisecond
	updateCheckTimeout        = 30 * time.Second
	webUIIdleTimeout          = time.Hour

	webUIDisabledManual = "manual"
	webUIDisabledIdle   = "idle"
)

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
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	return &Server{
		Runtime:                 rt,
		StopFunc:                stopFunc,
		addr:                    addr,
		staticFS:                sub,
		conns:                   map[net.Conn]struct{}{},
		closeCh:                 make(chan struct{}),
		webUIEnabled:            true,
		webUILastBrowserRequest: time.Now(),
		webUIIdleTimeout:        webUIIdleTimeout,
		shutdownCtx:             shutdownCtx,
		shutdownCancel:          shutdownCancel,
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
	s.startWebUIIdleTimer()
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
		go func(c net.Conn) {
			defer s.untrackConn(c)
			s.handleConn(c)
		}(conn)
	}
}

func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.shutdownCancel != nil {
			s.shutdownCancel()
		}
		s.shutdownWebUIIdleTimer()
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
	if len(s.conns) >= maxHTTPConnections {
		s.mu.Unlock()
		// This runs in the accept loop. A client that does not read must not
		// prevent other clients from connecting or the server from stopping.
		writeBytesWithTimeout(conn, 503, "text/plain; charset=utf-8", []byte("too many connections\n"), httpRejectWriteTimeout)
		_ = conn.Close()
		return false
	}
	s.conns[conn] = struct{}{}
	// Pair registration and Add under the same lock used by Close. Otherwise
	// Close can finish waiting before Serve adds this connection's handler.
	s.wg.Add(1)
	if len(s.conns) > s.connPeak {
		s.connPeak = len(s.conns)
	}
	s.mu.Unlock()
	return true
}

func (s *Server) untrackConn(conn net.Conn) {
	defer s.wg.Done()
	_ = conn.Close()
	s.mu.Lock()
	delete(s.conns, conn)
	if len(s.conns) == 0 && s.connPeak >= 64 {
		s.conns = map[net.Conn]struct{}{}
		s.connPeak = 0
	}
	s.mu.Unlock()
}

func (s *Server) handleConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)
	req, err := readRequest(br)
	if err != nil {
		if errors.Is(err, errUpdateInstallBodyTooLarge) {
			writeText(conn, 413, err.Error())
			return
		}
		writeText(conn, 400, err.Error())
		return
	}
	if !isWebUIControlPath(req.Path) && !s.admitWebUIRequest(req) {
		if !strings.HasPrefix(req.Path, "/api/") && req.Method == "GET" {
			s.handleDisabledWebUIPage(conn)
		} else {
			writeText(conn, 503, "WebUI disabled")
		}
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
	case "/api/rules/activity":
		s.handleRuleActivity(conn, req)
	case "/api/rules/condition-activity":
		s.handleRuleConditionActivity(conn, req)
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
	case "/api/update/releases":
		s.handleUpdateReleases(conn, req)
	case "/api/update/status":
		s.handleUpdateStatus(conn, req)
	case "/api/update/install":
		s.handleUpdateInstall(conn, req)
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
	payload := map[string]interface{}{
		"ok":      true,
		"version": buildinfo.CurrentVersion(),
		"pid":     os.Getpid(),
	}
	if updateService := s.updater(); updateService != nil {
		if token := strings.TrimSpace(updateService.HealthToken()); token != "" {
			payload["update_token"] = token
		}
	}
	writeJSON(conn, 200, payload)
}

func (s *Server) WebUIEnabled() bool {
	s.webUIMu.RLock()
	defer s.webUIMu.RUnlock()
	return s.webUIEnabled
}

func (s *Server) SetWebUIEnabled(enabled bool) {
	reason := ""
	if !enabled {
		reason = webUIDisabledManual
	}
	s.setWebUIEnabled(enabled, reason)
}

func (s *Server) setWebUIEnabled(enabled bool, reason string) {
	s.webUITransitionMu.Lock()
	defer s.webUITransitionMu.Unlock()
	now := time.Now()
	s.webUIMu.Lock()
	changed := s.webUIEnabled != enabled
	s.webUIEnabled = enabled
	if enabled {
		s.webUIDisabledReason = ""
		s.webUIDisabledAt = time.Time{}
		s.webUILastBrowserRequest = now
		s.startWebUIIdleTimerLocked(now)
	} else if changed {
		s.webUIDisabledReason = reason
		s.webUIDisabledAt = now.UTC()
		s.stopWebUIIdleTimerLocked()
	}
	status := s.webUIStatusLocked()
	s.webUIMu.Unlock()
	status.Paused = s.ServicePaused()
	if !enabled && changed {
		s.Runtime.Monitor().PublishTransientEvent("webui_status", status)
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

func (s *Server) webUIStatus() webUIStatusDTO {
	s.webUIMu.RLock()
	status := s.webUIStatusLocked()
	s.webUIMu.RUnlock()
	status.Paused = s.ServicePaused()
	return status
}

func (s *Server) webUIStatusLocked() webUIStatusDTO {
	status := webUIStatusDTO{
		Enabled:            s.webUIEnabled,
		AutoPaused:         !s.webUIEnabled && s.webUIDisabledReason == webUIDisabledIdle,
		DisabledReason:     s.webUIDisabledReason,
		IdleTimeoutSeconds: int64(s.webUIIdleTimeout / time.Second),
	}
	if !s.webUIDisabledAt.IsZero() {
		disabledAt := s.webUIDisabledAt.UTC()
		status.DisabledAt = &disabledAt
	}
	if s.webUIEnabled && s.webUIIdleTimeout > 0 && !s.webUILastBrowserRequest.IsZero() {
		deadline := s.webUILastBrowserRequest.Add(s.webUIIdleTimeout).UTC()
		status.IdleDeadlineAt = &deadline
	}
	return status
}

// admitWebUIRequest performs the enabled check and activity update under one
// lock. This prevents the idle timer from disabling the UI between those two
// operations while keeping control/tray traffic entirely outside the timer.
func (s *Server) admitWebUIRequest(req request) bool {
	s.webUIMu.Lock()
	defer s.webUIMu.Unlock()
	if !s.webUIEnabled {
		return false
	}
	if isBrowserWebUIActivity(req) {
		s.webUILastBrowserRequest = time.Now()
	}
	return true
}

func (s *Server) startWebUIIdleTimer() {
	now := time.Now()
	s.webUIMu.Lock()
	if s.webUIEnabled {
		s.webUILastBrowserRequest = now
		s.startWebUIIdleTimerLocked(now)
	}
	s.webUIMu.Unlock()
}

// Browser requests only update the timestamp. The timer is deliberately not
// reset for every request: it wakes at the old deadline, observes the newer
// timestamp and reschedules itself once. Thus an active UI does not generate
// timer churn or a polling goroutine.
func (s *Server) startWebUIIdleTimerLocked(now time.Time) {
	if !s.webUIEnabled || s.webUIIdleClosed || s.webUIIdleTimeout <= 0 || s.webUIIdleTimer != nil {
		return
	}
	deadline := s.webUILastBrowserRequest.Add(s.webUIIdleTimeout)
	delay := deadline.Sub(now)
	if delay <= 0 {
		delay = time.Nanosecond
	}
	s.webUIIdleGeneration++
	generation := s.webUIIdleGeneration
	hook := s.webUIIdleCallbackHook
	s.webUIIdleWG.Add(1)
	s.webUIIdleTimer = time.AfterFunc(delay, func() {
		defer s.webUIIdleWG.Done()
		if hook != nil {
			if doneHook := hook(); doneHook != nil {
				defer doneHook()
			}
		}
		s.handleWebUIIdleTimeout(generation)
	})
}

func (s *Server) stopWebUIIdleTimer() {
	s.webUIMu.Lock()
	s.stopWebUIIdleTimerLocked()
	s.webUIMu.Unlock()
	s.webUIIdleWG.Wait()
}

func (s *Server) stopWebUIIdleTimerLocked() {
	s.webUIIdleGeneration++
	if s.webUIIdleTimer != nil {
		if s.webUIIdleTimer.Stop() {
			s.webUIIdleWG.Done()
		}
		s.webUIIdleTimer = nil
	}
}

func (s *Server) shutdownWebUIIdleTimer() {
	s.webUIMu.Lock()
	s.webUIIdleClosed = true
	s.stopWebUIIdleTimerLocked()
	s.webUIMu.Unlock()
	s.webUIIdleWG.Wait()
}

func (s *Server) handleWebUIIdleTimeout(generation uint64) {
	s.webUITransitionMu.Lock()
	defer s.webUITransitionMu.Unlock()
	now := time.Now()
	s.webUIMu.Lock()
	if generation != s.webUIIdleGeneration || s.webUIIdleClosed {
		s.webUIMu.Unlock()
		return
	}
	s.webUIIdleTimer = nil
	if !s.webUIEnabled || s.webUIIdleTimeout <= 0 {
		s.webUIMu.Unlock()
		return
	}
	if now.Before(s.webUILastBrowserRequest.Add(s.webUIIdleTimeout)) {
		s.startWebUIIdleTimerLocked(now)
		s.webUIMu.Unlock()
		return
	}
	s.webUIEnabled = false
	s.webUIDisabledReason = webUIDisabledIdle
	s.webUIDisabledAt = now.UTC()
	status := s.webUIStatusLocked()
	s.webUIMu.Unlock()

	status.Paused = s.ServicePaused()
	s.Runtime.Monitor().AddLog("info", "WebUI automatically paused after %s without browser requests; proxy runtime remains active", s.webUIIdleTimeout)
	s.Runtime.Monitor().PublishTransientEvent("webui_status", status)
	s.Runtime.Monitor().DisableUI()
	util.ReleaseIdleMemory()
}

func (s *Server) handleDisabledWebUIPage(conn net.Conn) {
	status := s.webUIStatus()
	title := "WebUI отключён"
	detail := "Интерфейс управления отключён. Проксирование продолжает работать."
	hint := "Чтобы снова включить интерфейс, выберите «Включить WebUI» в меню значка pitchProx в системном трее."
	if status.Paused {
		title = "Сервис приостановлен"
		detail = "Сервис и WebUI приостановлены пользователем."
		hint = "Чтобы возобновить работу, выберите «Запустить» в меню значка pitchProx в системном трее."
	} else if status.AutoPaused {
		title = "WebUI приостановлен"
		detail = "В течение часа не было обращений из браузера, поэтому WebUI был автоматически приостановлен. Проксирование продолжает работать."
	}
	body := []byte("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>" + title + " — pitchProx</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f8fc;color:#16233a;font:16px system-ui,-apple-system,Segoe UI,sans-serif}.card{max-width:560px;margin:24px;padding:32px;border:1px solid #dce5f2;border-radius:18px;background:#fff;box-shadow:0 16px 44px #183d7514}h1{margin:0 0 12px;font-size:26px}p{line-height:1.55;color:#52627a}.brand{color:#086cf0;font-weight:750}.hint{margin-top:22px;padding:14px 16px;border-radius:12px;background:#edf5ff;color:#24466f}</style></head><body><main class=\"card\"><div class=\"brand\">pitchProx</div><h1>" + title + "</h1><p>" + detail + "</p><p class=\"hint\">" + hint + "</p></main></body></html>")
	writeBytes(conn, 503, "text/html; charset=utf-8", body)
}

func (s *Server) handleWebUIStatus(conn net.Conn) {
	writeJSON(conn, 200, s.webUIStatus())
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
	writeJSON(conn, 200, s.webUIStatus())
}

func (s *Server) handleWebUIDisable(conn net.Conn, req request) {
	if req.Method != "POST" {
		writeEmpty(conn, 405)
		return
	}
	s.SetWebUIEnabled(false)
	writeJSON(conn, 200, s.webUIStatus())
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
		s.updateMutationMu.Lock()
		if updateService := s.updater(); updateService != nil && updateService.Status().Busy {
			s.updateMutationMu.Unlock()
			writeText(conn, 409, "configuration cannot be changed while an application update is running")
			return
		}
		expectedUpdatedAt := cfg.UpdatedAt
		if err := s.Runtime.UpdateConfigIfCurrent(cfg, expectedUpdatedAt); err != nil {
			s.updateMutationMu.Unlock()
			if errors.Is(err, config.ErrConfigConflict) {
				writeText(conn, 409, err.Error())
				return
			}
			writeText(conn, 400, err.Error())
			return
		}
		current := s.Runtime.CurrentConfig()
		s.updateMutationMu.Unlock()
		writeJSON(conn, 200, current)
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

func (s *Server) handleRuleActivity(conn net.Conn, req request) {
	if req.Method != "GET" {
		writeEmpty(conn, 405)
		return
	}
	rawIDs := req.Query["id"]
	ids := make([]string, 0, min(len(rawIDs), 50))
	seen := make(map[string]struct{}, min(len(rawIDs), 50))
	for _, rawID := range rawIDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		if len(ids) >= 50 {
			writeText(conn, 400, "at most 50 rule ids are allowed")
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	points, err := parseNonNegativeInt(req.Query.Get("points"), 40)
	if err != nil || points < 2 || points > 60 {
		writeText(conn, 400, "points must be in 2..60")
		return
	}
	windowMinutes, err := parseNonNegativeInt(req.Query.Get("window_minutes"), 15)
	if err != nil || windowMinutes < 1 || windowMinutes > 60 {
		writeText(conn, 400, "window_minutes must be in 1..60")
		return
	}
	if retention := s.Runtime.CurrentConfig().RetentionMinutes; retention > 0 && windowMinutes > retention {
		windowMinutes = retention
	}
	data, err := s.Runtime.Monitor().RuleActivityTimeline(ids, time.Duration(windowMinutes)*time.Minute, points)
	if err != nil {
		writeText(conn, 500, err.Error())
		return
	}
	writeJSON(conn, 200, data)
}

func (s *Server) handleRuleConditionActivity(conn net.Conn, req request) {
	if req.Method != "GET" {
		writeEmpty(conn, 405)
		return
	}
	rawIDs := req.Query["id"]
	if len(rawIDs) != 1 || strings.TrimSpace(rawIDs[0]) == "" {
		writeText(conn, 400, "exactly one non-empty rule id is required")
		return
	}
	ruleID := strings.TrimSpace(rawIDs[0])
	windowMinutes, err := parseNonNegativeInt(req.Query.Get("window_minutes"), 15)
	if err != nil || windowMinutes < 1 || windowMinutes > 60 {
		writeText(conn, 400, "window_minutes must be in 1..60")
		return
	}
	limit, err := parseNonNegativeInt(req.Query.Get("limit"), 20)
	if err != nil || limit < 1 || limit > 100 {
		writeText(conn, 400, "limit must be in 1..100")
		return
	}
	if retention := s.Runtime.CurrentConfig().RetentionMinutes; retention > 0 && windowMinutes > retention {
		windowMinutes = retention
	}
	data, err := s.Runtime.Monitor().RuleConditionActivity(ruleID, time.Duration(windowMinutes)*time.Minute, limit)
	if err != nil {
		writeText(conn, 500, err.Error())
		return
	}
	writeJSON(conn, 200, data)
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

func (s *Server) handleUpdateReleases(conn net.Conn, req request) {
	if req.Method != "GET" {
		writeEmpty(conn, 405)
		return
	}
	if !isTrustedWebUIRequest(req) {
		writeText(conn, 403, "trusted WebUI request required")
		return
	}
	updateService := s.updater()
	if updateService == nil {
		writeText(conn, 503, "application updater is not available")
		return
	}
	baseCtx := s.shutdownCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, updateCheckTimeout)
	defer cancel()
	result, err := updateService.Check(ctx)
	if err != nil {
		writeText(conn, 500, fmt.Sprintf("check updates: %v", err))
		return
	}
	writeJSON(conn, 200, result)
}

func (s *Server) handleUpdateStatus(conn net.Conn, req request) {
	if req.Method != "GET" {
		writeEmpty(conn, 405)
		return
	}
	if !isTrustedWebUIRequest(req) {
		writeText(conn, 403, "trusted WebUI request required")
		return
	}
	updateService := s.updater()
	if updateService == nil {
		writeText(conn, 503, "application updater is not available")
		return
	}
	writeJSON(conn, 200, updateService.Status())
}

func (s *Server) handleUpdateInstall(conn net.Conn, req request) {
	if req.Method != "POST" {
		writeEmpty(conn, 405)
		return
	}
	if !isTrustedWebUIRequest(req) {
		writeText(conn, 403, "trusted WebUI request required")
		return
	}
	updateService := s.updater()
	if updateService == nil {
		writeText(conn, 503, "application updater is not available")
		return
	}
	if len(req.Body) == 0 {
		writeText(conn, 400, "request body is required")
		return
	}
	if len(req.Body) > maxUpdateInstallBodyBytes {
		writeText(conn, 413, "request body is too large")
		return
	}
	var payload updateInstallRequest
	decoder := json.NewDecoder(bytes.NewReader(req.Body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeText(conn, 400, fmt.Sprintf("invalid json: %v", err))
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		writeText(conn, 400, fmt.Sprintf("invalid json: %v", err))
		return
	}
	payload.Version = strings.TrimSpace(payload.Version)
	if payload.Version == "" || len(payload.Version) > maxUpdateVersionBytes {
		writeText(conn, 400, "version must be a non-empty release tag of at most 128 bytes")
		return
	}
	s.updateMutationMu.Lock()
	status, err := updateService.StartInstall(payload.Version)
	s.updateMutationMu.Unlock()
	if err != nil {
		writeText(conn, 409, err.Error())
		return
	}
	writeJSON(conn, 202, status)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing interface{}
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values are not allowed")
}

func isTrustedWebUIRequest(req request) bool {
	if strings.TrimSpace(req.Headers["x-pitchprox-webui"]) != "1" {
		return false
	}
	host := strings.TrimSpace(req.Headers["host"])
	if host == "" {
		return false
	}
	hostname := host
	switch {
	case strings.HasPrefix(host, "["):
		if strings.HasSuffix(host, "]") {
			hostname = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		} else {
			parsedHost, port, err := net.SplitHostPort(host)
			if err != nil || !validHTTPHostPort(port) {
				return false
			}
			hostname = parsedHost
		}
	case strings.Count(host, ":") == 1:
		parsedHost, port, err := net.SplitHostPort(host)
		if err != nil || !validHTTPHostPort(port) {
			return false
		}
		hostname = parsedHost
	case strings.Count(host, ":") > 1:
		if net.ParseIP(host) == nil {
			return false
		}
	}
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if hostname == "localhost" {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

func validHTTPHostPort(raw string) bool {
	port, err := strconv.Atoi(raw)
	return err == nil && port >= 1 && port <= 65535
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
	ch, cancel, ok := s.subscribeEventsIfEnabled()
	if !ok {
		writeText(conn, 503, "WebUI disabled")
		return
	}
	defer cancel()

	bw := bufio.NewWriter(conn)
	_ = conn.SetWriteDeadline(time.Now().Add(httpWriteTimeout))
	if err := writeHeaders(bw, 200, map[string]string{
		"Content-Type":  "text/event-stream",
		"Cache-Control": "no-cache",
		"Connection":    "keep-alive",
	}, -1); err != nil {
		return
	}

	_ = conn.SetReadDeadline(time.Time{})
	// EventSource.close sends EOF, but writes alone may not notice it until
	// the next heartbeat. Release its UI subscription as soon as the tab hides
	// or closes. Close and join this reader on every exit from the stream.
	peerClosed := make(chan struct{})
	go func() {
		var data [1]byte
		_, _ = conn.Read(data[:])
		close(peerClosed)
	}()
	defer func() {
		_ = conn.Close()
		<-peerClosed
	}()
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case <-peerClosed:
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(httpWriteTimeout))
			if err := writeSSE(bw, data); err != nil {
				return
			}
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(httpWriteTimeout))
			if _, err := bw.WriteString(": ping\n\n"); err != nil {
				return
			}
			if err := bw.Flush(); err != nil {
				return
			}
		}
	}
}

// subscribeEventsIfEnabled serializes the enabled check and subscription with
// SetWebUIEnabled. A concurrent disable either observes and closes this new
// subscriber through DisableUI, or wins first and prevents its creation.
func (s *Server) subscribeEventsIfEnabled() (<-chan []byte, func(), bool) {
	s.webUIMu.RLock()
	defer s.webUIMu.RUnlock()
	if !s.webUIEnabled {
		return nil, nil, false
	}
	_, ch, cancel := s.Runtime.Monitor().Subscribe()
	return ch, cancel, true
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
	headerBytes := 0
	headerCount := 0
	for {
		line, err := readLine(br)
		if err != nil {
			return request{}, err
		}
		if line == "" {
			break
		}
		headerCount++
		headerBytes += len(line)
		if headerCount > maxHTTPHeaders || headerBytes > maxHTTPHeaderBytes {
			return request{}, fmt.Errorf("request headers too large")
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
			if req.Path == "/api/update/install" && contentLength > maxUpdateInstallBodyBytes {
				return request{}, errUpdateInstallBodyTooLarge
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
	line, err := br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return "", fmt.Errorf("request line too long")
		}
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
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
	writeBytesWithTimeout(conn, status, contentType, body, httpWriteTimeout)
}

func writeBytesWithTimeout(conn net.Conn, status int, contentType string, body []byte, timeout time.Duration) {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
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
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 409:
		return "Conflict"
	case 413:
		return "Payload Too Large"
	case 500:
		return "Internal Server Error"
	case 503:
		return "Service Unavailable"
	default:
		return "Status"
	}
}

func isBrowserWebUIActivity(req request) bool {
	if !strings.HasPrefix(req.Path, "/api/") {
		return req.Method == "GET"
	}
	if isWebUIControlPath(req.Path) {
		return false
	}
	marked := strings.TrimSpace(req.Headers["x-pitchprox-webui"]) == "1" || req.Query.Get("_ui") == "1"
	if !marked {
		return false
	}
	if req.Path != "/api/ui/visibility" {
		return true
	}
	var payload uiVisibilityRequest
	return json.Unmarshal(req.Body, &payload) == nil && payload.Active
}

func shouldMarkUIActive(path string) bool {
	return path == "/api/snapshot" || path == "/api/events"
}

func isWebUIControlPath(path string) bool {
	switch path {
	case "/api/health", "/api/tray", "/api/control/stop", "/api/control/webui/status", "/api/control/webui/enable", "/api/control/webui/disable", "/api/control/service/status", "/api/control/service/pause", "/api/control/service/resume":
		return true
	default:
		return false
	}
}
