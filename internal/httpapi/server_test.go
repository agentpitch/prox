package httpapi

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/openai/pitchprox/internal/config"
	"github.com/openai/pitchprox/internal/monitor"
	"github.com/openai/pitchprox/internal/proxy"
)

type fakeRuntime struct {
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

func (r *fakeRuntime) CurrentConfig() config.Config { return config.Clone(r.cfg) }

func (r *fakeRuntime) UpdateConfig(cfg config.Config) error {
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
