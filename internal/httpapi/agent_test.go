package httpapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/control"
	"github.com/agentpitch/prox/internal/updater"
)

func startAgentTestServer(t *testing.T, setup func(*Server, *fakeRuntime)) (*Server, *fakeRuntime, string, *http.Client) {
	t.Helper()
	rt := newFakeRuntime(t, "127.0.0.1:0")
	srv, err := New("127.0.0.1:0", rt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(srv, rt)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	})
	return srv, rt, "http://" + srv.listener.Addr().String(), &http.Client{Timeout: 2 * time.Second}
}

func agentRequest(client *http.Client, method, url string, body []byte, headers map[string]string) updateRequestResult {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return updateRequestResult{err: err}
	}
	req.Header.Set("X-PitchProx-Agent", "1")
	for key, value := range headers {
		if strings.EqualFold(key, "Host") {
			req.Host = value
		} else {
			req.Header.Set(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return updateRequestResult{err: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return updateRequestResult{status: resp.StatusCode, body: data, err: err}
}

func expectAgentError(t *testing.T, result updateRequestResult, status int, code string) {
	t.Helper()
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.status != status {
		t.Fatalf("status=%d body=%s, want %d", result.status, result.body, status)
	}
	var response control.ErrorResponse
	if err := json.Unmarshal(result.body, &response); err != nil {
		t.Fatalf("error response must be JSON: %s: %v", result.body, err)
	}
	if response.Error.Code != code || response.Error.Message == "" {
		t.Fatalf("error=%+v, want code %s and message", response.Error, code)
	}
}

func TestAgentControlWorksWithDisabledWebUIWithoutDemand(t *testing.T) {
	srv, rt, base, client := startAgentTestServer(t, func(s *Server, _ *fakeRuntime) {
		s.PausedFunc = func() bool { return true }
		s.SetWebUIEnabled(false)
	})
	before := srv.webUILastBrowserRequest
	statusResult := agentRequest(client, "GET", base+"/api/control/agent/status?_ui=1", nil, map[string]string{"X-PitchProx-WebUI": "1"})
	if statusResult.err != nil || statusResult.status != 200 {
		t.Fatalf("agent status failed: %+v", statusResult)
	}
	var status control.Status
	if err := json.Unmarshal(statusResult.body, &status); err != nil {
		t.Fatal(err)
	}
	if status.ProtocolVersion != control.ProtocolVersion || status.PID == 0 || status.ListeningAddress != srv.listener.Addr().String() || !status.ServicePaused || status.WebUIEnabled {
		t.Fatalf("unexpected agent status: %+v", status)
	}
	getResult := agentRequest(client, "GET", base+"/api/control/agent/config", nil, nil)
	if getResult.err != nil || getResult.status != 200 {
		t.Fatalf("agent config failed: %+v", getResult)
	}
	var cfg config.Config
	if err := json.Unmarshal(getResult.body, &cfg); err != nil || !cfg.UpdatedAt.Equal(rt.CurrentConfig().UpdatedAt) || len(cfg.Rules) != 1 {
		t.Fatalf("GET did not export raw config: %s, %v", getResult.body, err)
	}
	if rt.mon.UIActive() || srv.WebUIEnabled() || !before.Equal(srv.webUILastBrowserRequest) {
		t.Fatal("agent control activated UI or extended its idle deadline")
	}
	if got := httpStatus(t, client, base+"/api/config"); got != 503 {
		t.Fatalf("regular WebUI unexpectedly enabled: %d", got)
	}
}

func TestAgentRequestsDoNotExtendEnabledWebUIDeadline(t *testing.T) {
	srv, rt, base, client := startAgentTestServer(t, nil)
	srv.webUIMu.Lock()
	srv.webUILastBrowserRequest = time.Now().Add(-30 * time.Minute)
	before := srv.webUILastBrowserRequest
	srv.webUIMu.Unlock()
	result := agentRequest(client, "GET", base+"/api/control/agent/status?_ui=1", nil, map[string]string{"X-PitchProx-WebUI": "1"})
	if result.err != nil || result.status != 200 {
		t.Fatalf("status request: %+v", result)
	}
	srv.webUIMu.RLock()
	after := srv.webUILastBrowserRequest
	srv.webUIMu.RUnlock()
	if rt.mon.UIActive() || !before.Equal(after) {
		t.Fatal("headless request renewed browser activity")
	}
}

func TestAgentControlRejectsBrowserAndForeignHostRequests(t *testing.T) {
	_, _, base, client := startAgentTestServer(t, nil)
	for name, headers := range map[string]map[string]string{
		"no marker":           {"X-PitchProx-Agent": ""},
		"foreign host":        {"Host": "example.com:18080"},
		"loopback lookalike":  {"Host": "127.0.0.1.example.com:18080"},
		"origin":              {"Origin": "http://127.0.0.1:18080"},
		"empty origin":        {"Origin": ""},
		"cross site":          {"Sec-Fetch-Site": "cross-site"},
		"same origin browser": {"Sec-Fetch-Site": "same-origin"},
	} {
		t.Run(name, func(t *testing.T) {
			expectAgentError(t, agentRequest(client, "GET", base+"/api/control/agent/config", nil, headers), 403, "forbidden")
		})
	}
	expectAgentError(t, agentRequest(client, "OPTIONS", base+"/api/control/agent/config", nil, nil), 405, "method_not_allowed")
	expectAgentError(t, agentRequest(client, "GET", base+"/api/control/agent/missing", nil, nil), 404, "not_found")
}

func TestAgentApplyStrictJSONRevisionAndPreview(t *testing.T) {
	var calls atomic.Int32
	requests := make(chan control.ConfigRequest, 4)
	srv, rt, base, client := startAgentTestServer(t, func(s *Server, _ *fakeRuntime) {
		s.SetWebUIEnabled(false)
		s.ApplyConfigFunc = func(req control.ConfigRequest) (control.ConfigResult, error) {
			calls.Add(1)
			requests <- req
			return control.ConfigResult{Config: req.Config, Applied: !req.DryRun}, nil
		}
	})
	cfgJSON, _ := json.Marshal(rt.CurrentConfig())
	revisionJSON, _ := json.Marshal(rt.CurrentConfig().UpdatedAt)
	valid := fmt.Sprintf(`{"config":%s,"expected_updated_at":%s}`, cfgJSON, revisionJSON)
	for _, tc := range []struct {
		name, body, code string
		status           int
	}{
		{"empty", "", "invalid_json", 400},
		{"missing config", fmt.Sprintf(`{"expected_updated_at":%s}`, revisionJSON), "invalid_config", 400},
		{"null config", `{"config":null}`, "invalid_json", 400},
		{"no revision", fmt.Sprintf(`{"config":%s}`, cfgJSON), "revision_required", 428},
		{"no revision even for PUT preview", fmt.Sprintf(`{"config":%s,"dry_run":true}`, cfgJSON), "revision_required", 428},
		{"unknown envelope", strings.TrimSuffix(valid, "}") + `,"unexpected":true}`, "invalid_json", 400},
		{"wrong case field", strings.Replace(valid, `"config":`, `"Config":`, 1), "invalid_json", 400},
		{"duplicate envelope", strings.TrimSuffix(valid, "}") + `,"config":{}}`, "invalid_json", 400},
		{"duplicate nested", `{"config":{"http":{"listen":"a","listen":"b"}}}`, "invalid_json", 400},
		{"unknown nested", `{"config":{"http":{"unexpected":true}}}`, "invalid_json", 400},
		{"null boolean", strings.TrimSuffix(valid, "}") + `,"dry_run":null}`, "invalid_json", 400},
		{"trailing document", valid + " {}", "invalid_json", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectAgentError(t, agentRequest(client, "PUT", base+"/api/control/agent/config", []byte(tc.body), nil), tc.status, tc.code)
		})
	}
	if calls.Load() != 0 {
		t.Fatal("malformed request reached runtime")
	}
	result := agentRequest(client, "PUT", base+"/api/control/agent/config", append([]byte{0xef, 0xbb, 0xbf}, []byte(valid)...), nil)
	if result.err != nil || result.status != 200 {
		t.Fatalf("valid apply: %+v", result)
	}
	if req := <-requests; req.DryRun || !req.ExpectedUpdatedAt.Equal(rt.CurrentConfig().UpdatedAt) {
		t.Fatalf("wrong apply callback: %+v", req)
	}
	result = agentRequest(client, "POST", base+"/api/control/agent/config/validate", []byte(fmt.Sprintf(`{"config":%s,"dry_run":false}`, cfgJSON)), nil)
	if result.err != nil || result.status != 200 {
		t.Fatalf("validate: %+v", result)
	}
	if req := <-requests; !req.DryRun || !req.ExpectedUpdatedAt.IsZero() {
		t.Fatalf("validate must force preview and allow omitted revision: %+v", req)
	}
	if rt.mon.UIActive() || srv.WebUIEnabled() {
		t.Fatal("agent apply or preview activated the WebUI")
	}
}

func TestAgentApplyReturnsStructuredConflictAndUpdaterBusy(t *testing.T) {
	var calls atomic.Int32
	srv, rt, base, client := startAgentTestServer(t, func(s *Server, rt *fakeRuntime) {
		s.ApplyConfigFunc = func(req control.ConfigRequest) (control.ConfigResult, error) {
			calls.Add(1)
			return control.ConfigResult{}, &control.APIError{Code: "revision_conflict", Message: "configuration changed", CurrentUpdatedAt: rt.CurrentConfig().UpdatedAt}
		}
	})
	body, _ := json.Marshal(control.ConfigRequest{Config: rt.CurrentConfig(), ExpectedUpdatedAt: rt.CurrentConfig().UpdatedAt})
	result := agentRequest(client, "PUT", base+"/api/control/agent/config", body, nil)
	expectAgentError(t, result, 409, "revision_conflict")
	var failure control.ErrorResponse
	_ = json.Unmarshal(result.body, &failure)
	if !failure.Error.CurrentUpdatedAt.Equal(rt.CurrentConfig().UpdatedAt) {
		t.Fatal("conflict omitted current revision")
	}
	srv.SetUpdater(&fakeUpdater{status: updater.Status{Busy: true}})
	expectAgentError(t, agentRequest(client, "PUT", base+"/api/control/agent/config", body, nil), 409, "update_busy")
	if calls.Load() != 1 {
		t.Fatal("busy updater did not prevent runtime mutation")
	}
}

func TestAgentParserBoundsBodyBeforeAllocationAndRejectsDuplicateHeaders(t *testing.T) {
	for _, raw := range []string{
		"PUT /api/control/agent/config HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8388609\r\n\r\n",
		"GET /api/control/agent/status HTTP/1.1\r\nHost: localhost\r\nHost: example.com\r\n\r\n",
	} {
		req, err := readRequest(bufio.NewReader(strings.NewReader(raw)))
		if err == nil || !isAgentControlPath(req.Path) || req.Body != nil {
			t.Fatalf("ambiguous/oversized request accepted or lost path: %+v, %v", req, err)
		}
	}
}

func TestAgentOversizedRequestReturnsStructuredErrorWithoutReadingBody(t *testing.T) {
	_, _, base, _ := startAgentTestServer(t, nil)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(base, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = io.WriteString(conn, "PUT /api/control/agent/config HTTP/1.1\r\nHost: localhost\r\nX-PitchProx-Agent: 1\r\nContent-Length: 8388609\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	expectAgentError(t, updateRequestResult{status: response.StatusCode, body: body, err: err}, 413, "request_too_large")
}

type agentPeerConn struct {
	net.Conn
	peer net.Addr
}

func (c agentPeerConn) RemoteAddr() net.Addr { return c.peer }

func TestAgentControlRequiresActualLoopbackPeer(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true}, {"127.0.0.2", true}, {"::1", true},
		{"::ffff:127.0.0.1", true}, {"192.0.2.1", false}, {"0.0.0.0", false},
	} {
		conn := agentPeerConn{peer: &net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 35000}}
		if got := isLoopbackPeer(conn); got != tc.want {
			t.Fatalf("loopback peer %q = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestAgentApplySerializesWithUpdaterInstall(t *testing.T) {
	entered, proceed := make(chan struct{}), make(chan struct{})
	up := &observingInstallUpdater{fakeUpdater: &fakeUpdater{startStatus: updater.Status{Busy: true}}, started: make(chan struct{})}
	_, rt, base, client := startAgentTestServer(t, func(s *Server, _ *fakeRuntime) {
		s.SetUpdater(up)
		s.ApplyConfigFunc = func(req control.ConfigRequest) (control.ConfigResult, error) {
			close(entered)
			<-proceed
			return control.ConfigResult{Config: req.Config, Applied: true}, nil
		}
	})
	body, _ := json.Marshal(control.ConfigRequest{Config: rt.CurrentConfig(), ExpectedUpdatedAt: rt.CurrentConfig().UpdatedAt})
	applyDone := make(chan updateRequestResult, 1)
	go func() { applyDone <- agentRequest(client, "PUT", base+"/api/control/agent/config", body, nil) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("apply callback did not start")
	}
	installDone := make(chan updateRequestResult, 1)
	go func() {
		installDone <- executeUpdateRequest(client, "POST", base+"/api/update/install", []byte(`{"version":"v1.2.0"}`), true, "")
	}()
	select {
	case <-up.started:
		close(proceed)
		t.Fatal("updater started while config mutation was in progress")
	case <-time.After(30 * time.Millisecond):
	}
	close(proceed)
	if result := <-applyDone; result.err != nil || result.status != 200 {
		t.Fatalf("apply failed: %+v", result)
	}
	if result := <-installDone; result.err != nil || result.status != 202 {
		t.Fatalf("install failed: %+v", result)
	}
}

func TestListenerHandoffKeepsMutationGuardAcrossOldAndNewServers(t *testing.T) {
	entered, proceed := make(chan struct{}), make(chan struct{})
	up := &observingInstallUpdater{fakeUpdater: &fakeUpdater{startStatus: updater.Status{Busy: true}}, started: make(chan struct{})}
	old, rt, oldURL, client := startAgentTestServer(t, func(s *Server, _ *fakeRuntime) {
		s.SetUpdater(up)
		s.ApplyConfigFunc = func(req control.ConfigRequest) (control.ConfigResult, error) {
			close(entered)
			<-proceed
			return control.ConfigResult{Config: req.Config, Applied: true}, nil
		}
	})
	replacement, _, newURL, _ := startAgentTestServer(t, func(s *Server, _ *fakeRuntime) {
		s.SetUpdater(up)
		s.CopyWebUIStateFrom(old)
	})
	if old.mutationGuard() != replacement.mutationGuard() {
		t.Fatal("listener replacement lost updater/config mutation exclusion")
	}
	body, _ := json.Marshal(control.ConfigRequest{Config: rt.CurrentConfig(), ExpectedUpdatedAt: rt.CurrentConfig().UpdatedAt})
	applyDone := make(chan updateRequestResult, 1)
	go func() { applyDone <- agentRequest(client, "PUT", oldURL+"/api/control/agent/config", body, nil) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("old listener apply did not start")
	}
	installDone := make(chan updateRequestResult, 1)
	go func() {
		installDone <- executeUpdateRequest(client, "POST", newURL+"/api/update/install", []byte(`{"version":"v1.2.0"}`), true, "")
	}()
	select {
	case <-up.started:
		close(proceed)
		t.Fatal("new listener updater bypassed an old listener config mutation")
	case <-time.After(30 * time.Millisecond):
	}
	close(proceed)
	if result := <-applyDone; result.err != nil || result.status != 200 {
		t.Fatalf("old listener apply: %+v", result)
	}
	if result := <-installDone; result.err != nil || result.status != 202 {
		t.Fatalf("new listener update: %+v", result)
	}
}

func TestLegacyWebUIConfigUsesProgramActivationCallback(t *testing.T) {
	requests := make(chan control.ConfigRequest, 1)
	_, rt, base, client := startAgentTestServer(t, func(s *Server, _ *fakeRuntime) {
		s.ApplyConfigFunc = func(req control.ConfigRequest) (control.ConfigResult, error) {
			requests <- req
			return control.ConfigResult{Config: req.Config, Applied: true}, nil
		}
	})
	cfg := rt.CurrentConfig()
	cfg.UpdatedAt = time.Time{} // Older WebUI clients omitted this precondition.
	body, _ := json.Marshal(cfg)
	result := executeUpdateRequest(client, "PUT", base+"/api/config", body, false, "")
	if result.err != nil || result.status != 200 {
		t.Fatalf("legacy PUT: %+v", result)
	}
	select {
	case req := <-requests:
		if !req.AllowDisruptive || req.DryRun || !req.ExpectedUpdatedAt.Equal(rt.CurrentConfig().UpdatedAt) {
			t.Fatalf("legacy PUT activation request: %+v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("legacy PUT bypassed the runtime activation callback")
	}
	var response config.Config
	if err := json.Unmarshal(result.body, &response); err != nil || len(response.Rules) != len(cfg.Rules) {
		t.Fatalf("legacy PUT response shape changed: %s", result.body)
	}
}

func TestCopyWebUIStatePreservesIdleDeadlineAndDisabledState(t *testing.T) {
	rt := newFakeRuntime(t, "127.0.0.1:0")
	old, _ := New("127.0.0.1:0", rt, nil)
	defer old.Close()
	replacement, _ := New("127.0.0.1:0", rt, nil)
	defer replacement.Close()
	if err := replacement.Listen(); err != nil {
		t.Fatal(err)
	}
	old.webUILastBrowserRequest = time.Now().Add(-30 * time.Minute)
	replacement.CopyWebUIStateFrom(old)
	if !replacement.webUILastBrowserRequest.Equal(old.webUILastBrowserRequest) || !replacement.WebUIEnabled() {
		t.Fatal("listener migration renewed the UI idle deadline")
	}
	old.SetWebUIEnabled(false)
	replacement.CopyWebUIStateFrom(old)
	if replacement.WebUIEnabled() || replacement.webUIIdleTimer != nil || replacement.webUIDisabledReason != old.webUIDisabledReason {
		t.Fatal("listener migration lost disabled UI state")
	}
}

func TestRetireDrainsExistingResponseAndBoundsOpenStreams(t *testing.T) {
	for _, finishResponse := range []bool{true, false} {
		t.Run(fmt.Sprint(finishResponse), func(t *testing.T) {
			srv, _ := New("127.0.0.1:0", newFakeRuntime(t, "127.0.0.1:0"), nil)
			defer srv.Close()
			if err := srv.Listen(); err != nil {
				t.Fatal(err)
			}
			server, client := net.Pipe()
			defer client.Close()
			if !srv.trackConn(server) {
				t.Fatal("failed to track response")
			}
			done := make(chan error, 1)
			go func() { done <- srv.Retire(100 * time.Millisecond) }()
			if finishResponse {
				responseDone := make(chan struct{})
				go func() {
					writeJSON(server, 200, map[string]bool{"applied": true})
					srv.untrackConn(server)
					close(responseDone)
				}()
				_ = client.SetReadDeadline(time.Now().Add(time.Second))
				response, err := http.ReadResponse(bufio.NewReader(client), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || !bytes.Contains(body, []byte(`"applied":true`)) {
					t.Fatalf("retirement truncated response: %s, %v", body, err)
				}
				<-responseDone
			} else {
				// A stuck handler must be unblocked by the forced connection close.
				go func() {
					_, _ = server.Read(make([]byte, 1))
					srv.untrackConn(server)
				}()
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("retirement exceeded its grace period")
			}
		})
	}
}
