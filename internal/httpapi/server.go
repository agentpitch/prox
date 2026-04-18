package httpapi

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/openai/pitchprox/internal/config"
	"github.com/openai/pitchprox/internal/monitor"
	"github.com/openai/pitchprox/internal/proxy"
	embedded "github.com/openai/pitchprox/internal/webui"
)

var ErrClosed = http.ErrServerClosed

type Runtime interface {
	CurrentConfig() config.Config
	UpdateConfig(config.Config) error
	Monitor() *monitor.Bus
	TestProxy(config.ProxyProfile, string) (proxy.ProxyTestResult, error)
}

type Server struct {
	Runtime  Runtime
	StopFunc func()
	srv      *http.Server
}

type proxyTestRequest struct {
	Proxy  config.ProxyProfile `json:"proxy"`
	Target string              `json:"target"`
}

func New(addr string, rt Runtime, stopFunc func()) (*Server, error) {
	sub, err := fs.Sub(embedded.FS, "dist")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	s := &Server{Runtime: rt, StopFunc: stopFunc}
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/snapshot", s.handleSnapshot)
	mux.HandleFunc("/api/tray", s.handleTray)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/proxy-test", s.handleProxyTest)
	mux.HandleFunc("/api/control/stop", s.handleControlStop)
	mux.Handle("/", http.FileServer(http.FS(sub)))
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           loggingMiddleware(rt.Monitor(), mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

func (s *Server) Start() error { return s.srv.ListenAndServe() }
func (s *Server) Close() error { return s.srv.Close() }

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.Runtime.CurrentConfig())
	case http.MethodPut:
		var cfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
			return
		}
		if err := s.Runtime.UpdateConfig(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, s.Runtime.CurrentConfig())
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Runtime.Monitor().Snapshot())
}

func (s *Server) handleTray(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Runtime.Monitor().TrayView(12))
}

func (s *Server) handleProxyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req proxyTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}
	result, err := s.Runtime.TestProxy(req.Proxy, req.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleControlStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "stopping": true})
	if s.StopFunc != nil {
		go func() {
			time.Sleep(150 * time.Millisecond)
			s.StopFunc()
		}()
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_, ch, cancel := s.Runtime.Monitor().Subscribe()
	defer cancel()
	snap, _ := json.Marshal(monitor.Event{Type: "snapshot", Data: s.Runtime.Monitor().Snapshot()})
	_, _ = fmt.Fprintf(w, "data: %s\n\n", snap)
	flusher.Flush()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func loggingMiddleware(bus *monitor.Bus, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bus != nil && shouldMarkUIActive(r.URL.Path) {
			bus.MarkUIActive()
		}
		next.ServeHTTP(w, r)
	})
}

func shouldMarkUIActive(path string) bool {
	if !strings.HasPrefix(path, "/api/") {
		return false
	}
	switch path {
	case "/api/health", "/api/tray", "/api/control/stop":
		return false
	default:
		return true
	}
}
