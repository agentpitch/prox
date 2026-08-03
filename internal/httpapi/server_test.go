package httpapi

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/monitor"
	"github.com/agentpitch/prox/internal/proxy"
)

type fakeRuntime struct {
	mu  sync.RWMutex
	cfg config.Config
	mon *monitor.Bus
}

func newFakeRuntime(t *testing.T, addr string) *fakeRuntime {
	t.Helper()
	mon, err := monitor.NewBus(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatalf("NewBus: %v", err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	return &fakeRuntime{
		cfg: config.Config{
			UpdatedAt:   time.Now().UTC(),
			HTTP:        config.HTTPConfig{Listen: addr},
			Transparent: config.TransparentConfig{ListenerPort: 26001, SniffBytes: 4096, SniffTimeout: 1500},
			Rules: []config.Rule{{
				ID:           "default",
				Name:         "Default",
				Enabled:      true,
				Applications: "*",
				TargetHosts:  "Any",
				TargetPorts:  "Any",
				Action:       config.ActionDirect,
			}},
		},
		mon: mon,
	}
}

func (r *fakeRuntime) CurrentConfig() config.Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return config.Clone(r.cfg)
}

func (r *fakeRuntime) UpdateConfig(cfg config.Config) error {
	return r.UpdateConfigIfCurrent(cfg, time.Time{})
}

func (r *fakeRuntime) UpdateConfigIfCurrent(cfg config.Config, expectedUpdatedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !expectedUpdatedAt.IsZero() && !expectedUpdatedAt.Equal(r.cfg.UpdatedAt) {
		return config.ErrConfigConflict
	}
	updatedAt := time.Now().UTC()
	if !updatedAt.After(r.cfg.UpdatedAt) {
		updatedAt = r.cfg.UpdatedAt.Add(time.Nanosecond)
	}
	cfg.UpdatedAt = updatedAt
	r.cfg = config.Clone(cfg)
	return nil
}

func (r *fakeRuntime) Monitor() *monitor.Bus { return r.mon }

func (r *fakeRuntime) TestProxy(config.ProxyProfile, string) (proxy.ProxyTestResult, error) {
	return proxy.ProxyTestResult{OK: true}, nil
}

func TestServerConnectionChurnReleasesTrackedConnections(t *testing.T) {
	addr := freeHTTPAddr(t)
	srv, err := New(addr, newFakeRuntime(t, addr), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	defer func() {
		if err := srv.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		select {
		case err := <-done:
			if err != nil && err != ErrClosed {
				t.Fatalf("Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Serve did not return after Close")
		}
	}()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	for i := 0; i < 500; i++ {
		resp, err := client.Get("http://" + addr + "/api/health")
		if err != nil {
			t.Fatalf("GET health #%d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET health #%d status = %d, want 200", i, resp.StatusCode)
		}
	}
	waitNoTrackedConnections(t, srv)
}

func TestConfigPUTUsesUpdatedAtAsOptimisticToken(t *testing.T) {
	addr := freeHTTPAddr(t)
	runtime := newFakeRuntime(t, addr)
	srv, err := New(addr, runtime, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})

	client := &http.Client{Timeout: 2 * time.Second}
	put := func(candidate config.Config) (int, string, config.Config) {
		t.Helper()
		body, err := json.Marshal(candidate)
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		req, err := http.NewRequest(http.MethodPut, "http://"+addr+"/api/config", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("new PUT config request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("PUT config: %v", err)
		}
		defer resp.Body.Close()
		var saved config.Config
		if resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(&saved); err != nil {
				t.Fatalf("decode saved config: %v", err)
			}
		}
		return resp.StatusCode, resp.Status, saved
	}

	initial := runtime.CurrentConfig()
	first := config.Clone(initial)
	first.RetentionMinutes = 8
	status, _, saved := put(first)
	if status != http.StatusOK {
		t.Fatalf("matching PUT status = %d, want 200", status)
	}
	if saved.RetentionMinutes != 8 || !saved.UpdatedAt.After(initial.UpdatedAt) {
		t.Fatalf("matching PUT response = %+v", saved)
	}

	stale := config.Clone(initial)
	stale.RetentionMinutes = 9
	status, statusText, _ := put(stale)
	if status != http.StatusConflict || statusText != "409 Conflict" {
		t.Fatalf("stale PUT status = %q, want 409 Conflict", statusText)
	}
	if got := runtime.CurrentConfig(); got.RetentionMinutes != 8 || !got.UpdatedAt.Equal(saved.UpdatedAt) {
		t.Fatalf("stale PUT changed config: saved=%+v current=%+v", saved, got)
	}

	legacy := config.Clone(stale)
	legacy.UpdatedAt = time.Time{}
	legacy.RetentionMinutes = 10
	status, _, legacySaved := put(legacy)
	if status != http.StatusOK {
		t.Fatalf("legacy zero-timestamp PUT status = %d, want 200", status)
	}
	if legacySaved.RetentionMinutes != 10 || !legacySaved.UpdatedAt.After(saved.UpdatedAt) {
		t.Fatalf("legacy PUT response = %+v", legacySaved)
	}
}

func TestShouldMarkUIActiveOnlyForLiveEndpoints(t *testing.T) {
	tests := map[string]bool{
		"/api/snapshot":       true,
		"/api/events":         true,
		"/api/config":         false,
		"/api/proxy-test":     false,
		"/api/dropped":        false,
		"/api/rules/activity": false,
		"/api/health":         false,
		"/":                   false,
	}
	for path, want := range tests {
		if got := shouldMarkUIActive(path); got != want {
			t.Errorf("shouldMarkUIActive(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestDisableWebUICannotLeaveLateEventSubscriber(t *testing.T) {
	runtime := newFakeRuntime(t, freeHTTPAddr(t))
	srv, err := New(runtime.cfg.HTTP.Listen, runtime, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 200; i++ {
		srv.SetWebUIEnabled(true)
		start := make(chan struct{})
		done := make(chan struct{})
		go func() {
			close(start)
			_, _, _ = srv.subscribeEventsIfEnabled()
			close(done)
		}()
		<-start
		srv.SetWebUIEnabled(false)
		<-done
		if subscribers := runtime.mon.DiagnosticStats().Subscribers; subscribers != 0 {
			t.Fatalf("iteration %d left %d event subscribers after disable", i, subscribers)
		}
	}
}

func TestRuleActivityEndpointReturnsOnlyRequestedBoundedSeries(t *testing.T) {
	addr := freeHTTPAddr(t)
	runtime := newFakeRuntime(t, addr)
	runtime.mon.AddRuleConnection("default", "Default", config.ActionDirect)
	runtime.mon.AddRuleTraffic("default", "Default", config.ActionProxy, 120, 340)

	srv, err := New(addr, runtime, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/api/rules/activity?id=default&points=40&window_minutes=5")
	if err != nil {
		t.Fatalf("GET activity: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET activity status = %d, want 200", resp.StatusCode)
	}
	var timeline monitor.RuleActivityTimeline
	if err := json.NewDecoder(resp.Body).Decode(&timeline); err != nil {
		t.Fatalf("decode timeline: %v", err)
	}
	if timeline.Points != 40 || len(timeline.Series) != 1 || len(timeline.Series[0].Buckets) != 40 {
		t.Fatalf("unexpected timeline: %+v", timeline)
	}
	if timeline.Series[0].RuleID != "default" || timeline.Series[0].Connections != 1 {
		t.Fatalf("unexpected series: %+v", timeline.Series[0])
	}

	longID := strings.Repeat("opaque-", 45)
	opaqueIDs := []string{"Foo", "foo", "foo,bar", longID}
	for _, id := range opaqueIDs {
		runtime.mon.AddRuleConnection(id, id, config.ActionDirect)
	}
	query := url.Values{"points": {"40"}, "window_minutes": {"5"}}
	for _, id := range opaqueIDs {
		query.Add("id", id)
	}
	resp, err = client.Get("http://" + addr + "/api/rules/activity?" + query.Encode())
	if err != nil {
		t.Fatalf("GET opaque activity: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET opaque activity status = %d, want 200", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&timeline); err != nil {
		t.Fatalf("decode opaque timeline: %v", err)
	}
	if len(timeline.Series) != len(opaqueIDs) {
		t.Fatalf("opaque series count = %d, want %d", len(timeline.Series), len(opaqueIDs))
	}
	for i, series := range timeline.Series {
		if series.RuleID != opaqueIDs[i] || series.Connections != 1 {
			t.Fatalf("opaque series %d = %+v, want id %q", i, series, opaqueIDs[i])
		}
	}

	resp, err = client.Get("http://" + addr + "/api/rules/activity?id=default&points=61")
	if err != nil {
		t.Fatalf("GET invalid activity: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET invalid activity status = %d, want 400", resp.StatusCode)
	}
}

func TestServerDisabledWebUIKeepsControlEndpointsAvailable(t *testing.T) {
	addr := freeHTTPAddr(t)
	srv, err := New(addr, newFakeRuntime(t, addr), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	defer func() {
		_ = srv.Close()
		<-done
	}()

	srv.SetWebUIEnabled(false)
	client := &http.Client{Timeout: 2 * time.Second}
	if status := httpStatus(t, client, "http://"+addr+"/"); status != http.StatusServiceUnavailable {
		t.Fatalf("GET / status = %d, want 503", status)
	}
	if status := httpStatus(t, client, "http://"+addr+"/api/health"); status != http.StatusOK {
		t.Fatalf("GET health status = %d, want 200", status)
	}
	if status := httpStatus(t, client, "http://"+addr+"/api/control/webui/status"); status != http.StatusOK {
		t.Fatalf("GET webui status = %d, want 200", status)
	}
	if status := httpStatus(t, client, "http://"+addr+"/api/control/service/status"); status != http.StatusOK {
		t.Fatalf("GET service status = %d, want 200", status)
	}
}

func TestServerDroppedConnectionsAPI(t *testing.T) {
	addr := freeHTTPAddr(t)
	rt := newFakeRuntime(t, addr)
	now := time.Now().UTC().Truncate(time.Second)
	rt.mon.UpsertConnection(monitor.Connection{
		ID:            "blocked-api-1",
		PID:           77,
		ExePath:       `C:\Apps\blocked-api.exe`,
		OriginalIP:    "203.0.113.77",
		OriginalPort:  443,
		Hostname:      "blocked-api.example",
		RuleID:        "deny",
		RuleName:      "Deny",
		Action:        config.ActionBlock,
		State:         "blocked",
		CreatedAt:     now,
		LastUpdatedAt: now,
		Count:         1,
	})

	srv, err := New(addr, rt, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	defer func() {
		_ = srv.Close()
		<-done
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/api/dropped?q=blocked-api&limit=100")
	if err != nil {
		t.Fatalf("GET dropped: %v", err)
	}
	var page droppedResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		_ = resp.Body.Close()
		t.Fatalf("decode dropped: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET dropped status = %d, want 200", resp.StatusCode)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("dropped page total=%d len=%d, want one item", page.Total, len(page.Items))
	}

	body, _ := json.Marshal(droppedDeleteRequest{IDs: []string{page.Items[0].DropID}})
	req, err := http.NewRequest(http.MethodDelete, "http://"+addr+"/api/dropped", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new delete request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DELETE dropped: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE dropped status = %d, want 200", resp.StatusCode)
	}

	resp, err = client.Get("http://" + addr + "/api/dropped?q=blocked-api&limit=100")
	if err != nil {
		t.Fatalf("GET dropped after delete: %v", err)
	}
	page = droppedResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		_ = resp.Body.Close()
		t.Fatalf("decode dropped after delete: %v", err)
	}
	_ = resp.Body.Close()
	if page.Total != 0 {
		t.Fatalf("dropped total after delete = %d, want 0", page.Total)
	}
}

func waitNoTrackedConnections(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		n := len(srv.conns)
		srv.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.mu.Lock()
	n := len(srv.conns)
	srv.mu.Unlock()
	t.Fatalf("tracked connections = %d, want 0", n)
}

func httpStatus(t *testing.T, client *http.Client, url string) int {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func freeHTTPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free addr: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close free addr listener: %v", err)
	}
	return addr
}
