package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/agentpitch/prox/internal/buildinfo"
	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/control"
)

func isAgentControlPath(path string) bool {
	return strings.HasPrefix(path, "/api/control/agent/")
}

func isTrustedAgentRequest(req request) bool {
	if strings.TrimSpace(req.Headers["x-pitchprox-agent"]) != "1" || !isTrustedLoopbackHost(req.Headers["host"]) {
		return false
	}
	// Browser origins never belong to the headless protocol. The non-simple
	// marker header also prevents cross-origin requests without a preflight;
	// this API does not grant CORS access or accept OPTIONS preflights.
	if _, present := req.Headers["origin"]; present {
		return false
	}
	site := strings.ToLower(strings.TrimSpace(req.Headers["sec-fetch-site"]))
	return site == "" || site == "none"
}

func isLoopbackPeer(conn net.Conn) bool {
	if conn.RemoteAddr() == nil {
		return false
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handleAgentControl(conn net.Conn, req request) {
	if !isTrustedAgentRequest(req) || !isLoopbackPeer(conn) {
		writeAgentError(conn, 403, &control.APIError{Code: "forbidden", Message: "local agent request required"})
		return
	}
	switch req.Path {
	case "/api/control/agent/status":
		if req.Method != "GET" {
			writeAgentMethodError(conn)
			return
		}
		cfg := s.Runtime.CurrentConfig()
		s.mu.Lock()
		address := s.addr
		if s.listener != nil {
			address = s.listener.Addr().String()
		}
		s.mu.Unlock()
		writeJSON(conn, 200, control.Status{
			ProtocolVersion: control.ProtocolVersion,
			Version:         buildinfo.CurrentVersion(), PID: os.Getpid(),
			UpdatedAt: cfg.UpdatedAt, ListeningAddress: address,
			ServicePaused: s.ServicePaused(), WebUIEnabled: s.WebUIEnabled(),
		})
	case "/api/control/agent/config":
		switch req.Method {
		case "GET":
			writeJSON(conn, 200, s.Runtime.CurrentConfig())
		case "PUT":
			s.handleAgentConfigApply(conn, req, false)
		default:
			writeAgentMethodError(conn)
		}
	case "/api/control/agent/config/validate":
		if req.Method != "POST" {
			writeAgentMethodError(conn)
			return
		}
		s.handleAgentConfigApply(conn, req, true)
	default:
		writeAgentError(conn, 404, &control.APIError{Code: "not_found", Message: "unknown agent endpoint"})
	}
}

func (s *Server) handleAgentConfigApply(conn net.Conn, req request, validateOnly bool) {
	var payload control.ConfigRequest
	if err := control.DecodeJSON(req.Body, &payload); err != nil {
		writeAgentError(conn, 400, &control.APIError{Code: "invalid_json", Message: err.Error()})
		return
	}
	// Decoding a missing or null struct otherwise silently supplies an empty
	// configuration, which must never replace an existing user's rules.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(bytes.TrimPrefix(req.Body, []byte{0xef, 0xbb, 0xbf}), &fields)
	if raw := bytes.TrimSpace(fields["config"]); len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		writeAgentError(conn, 400, &control.APIError{Code: "invalid_config", Message: "config object is required"})
		return
	}
	if !validateOnly && payload.ExpectedUpdatedAt.IsZero() {
		writeAgentError(conn, 428, &control.APIError{Code: "revision_required", Message: "expected_updated_at is required; read the current configuration first"})
		return
	}
	if validateOnly {
		payload.DryRun = true
	}
	if s.ApplyConfigFunc == nil {
		writeAgentError(conn, 503, &control.APIError{Code: "unavailable", Message: "agent configuration control is unavailable"})
		return
	}
	// Share the lock with WebUI PUT and updater installation. A replacement
	// listener is retired asynchronously by the runtime after this call.
	mutationMu := s.mutationGuard()
	mutationMu.Lock()
	if service := s.updater(); service != nil && service.Status().Busy {
		mutationMu.Unlock()
		writeAgentError(conn, 409, &control.APIError{Code: "update_busy", Message: "configuration cannot be changed while an application update is running"})
		return
	}
	result, err := s.ApplyConfigFunc(payload)
	mutationMu.Unlock()
	if err != nil {
		var apiErr *control.APIError
		if !errors.As(err, &apiErr) {
			if errors.Is(err, config.ErrConfigConflict) {
				apiErr = &control.APIError{Code: "revision_conflict", Message: err.Error(), CurrentUpdatedAt: s.Runtime.CurrentConfig().UpdatedAt}
			} else {
				apiErr = &control.APIError{Code: "activation_failed", Message: err.Error()}
			}
		}
		writeAgentError(conn, agentErrorStatus(apiErr.Code), apiErr)
		return
	}
	writeJSON(conn, 200, result)
}

func agentErrorStatus(code string) int {
	switch code {
	case "revision_conflict", "disruptive_change", "update_busy":
		return 409
	case "revision_required":
		return 428
	case "invalid_config", "invalid_json":
		return 400
	case "unavailable":
		return 503
	default:
		return 500
	}
}

func writeAgentError(conn net.Conn, status int, err *control.APIError) {
	writeJSON(conn, status, control.ErrorResponse{Error: *err})
}

func writeAgentMethodError(conn net.Conn) {
	writeAgentError(conn, 405, &control.APIError{Code: "method_not_allowed", Message: "method not allowed"})
}
