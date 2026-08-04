package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/monitor"
	"github.com/agentpitch/prox/internal/proxy"
	"github.com/agentpitch/prox/internal/updater"
)

type fakeRuntime struct {
	mu  sync.RWMutex
	cfg config.Config
	mon *monitor.Bus
}

type fakeUpdater struct {
	mu               sync.Mutex
	checkResult      updater.CheckResult
	checkErr         error
	status           updater.Status
	startStatus      updater.Status
	startErr         error
	healthToken      string
	checkCalls       int
	statusCalls      int
	installCalls     int
	installedVersion string
	checkTimeout     time.Duration
}

type blockingConfigRuntime struct {
	*fakeRuntime
	startedOnce sync.Once
	started     chan struct{}
	proceed     chan struct{}
}

func (r *blockingConfigRuntime) UpdateConfigIfCurrent(cfg config.Config, expectedUpdatedAt time.Time) error {
	r.startedOnce.Do(func() { close(r.started) })
	<-r.proceed
	return r.fakeRuntime.UpdateConfigIfCurrent(cfg, expectedUpdatedAt)
}

type observingInstallUpdater struct {
	*fakeUpdater
	startedOnce sync.Once
	started     chan struct{}
}

func (u *observingInstallUpdater) StartInstall(version string) (updater.Status, error) {
	u.startedOnce.Do(func() { close(u.started) })
	return u.fakeUpdater.StartInstall(version)
}

type cancellationAwareUpdater struct {
	*fakeUpdater
	startedOnce  sync.Once
	canceledOnce sync.Once
	started      chan struct{}
	canceled     chan struct{}
}

func (u *cancellationAwareUpdater) Check(ctx context.Context) (updater.CheckResult, error) {
	u.startedOnce.Do(func() { close(u.started) })
	<-ctx.Done()
	u.canceledOnce.Do(func() { close(u.canceled) })
	return updater.CheckResult{}, ctx.Err()
}

func (f *fakeUpdater) Check(ctx context.Context) (updater.CheckResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkCalls++
	if deadline, ok := ctx.Deadline(); ok {
		f.checkTimeout = time.Until(deadline)
	}
	return f.checkResult, f.checkErr
}

func (f *fakeUpdater) StartInstall(version string) (updater.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installCalls++
	f.installedVersion = version
	return f.startStatus, f.startErr
}

func (f *fakeUpdater) Status() updater.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusCalls++
	return f.status
}

func (f *fakeUpdater) HealthToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.healthToken
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

func TestUpdateAPIReleasesStatusInstallAndHealth(t *testing.T) {
	published := time.Date(2026, 8, 4, 12, 30, 0, 0, time.UTC)
	updateService := &fakeUpdater{
		checkResult: updater.CheckResult{
			CurrentVersion:  "v0.43-rc.4",
			LatestVersion:   "v0.44",
			UpdateAvailable: true,
			Releases: []updater.Release{{
				Version:      "v0.44",
				Name:         "Stable",
				PublishedAt:  published,
				Installable:  true,
				Verification: "manifest",
			}},
		},
		status:      updater.Status{Phase: updater.PhaseDownloading, Busy: true, Version: "v0.44", DownloadedBytes: 10, TotalBytes: 100},
		startStatus: updater.Status{Phase: updater.PhaseChecking, Busy: true, Version: "v0.44"},
		healthToken: "handoff-token",
	}
	srv, baseURL, client := startUpdateTestServer(t, updateService)

	statusCode, body := performUpdateRequest(t, client, http.MethodGet, baseURL+"/api/update/releases", nil, true, "")
	if statusCode != http.StatusOK {
		t.Fatalf("GET releases status = %d body=%q, want 200", statusCode, body)
	}
	var releases updater.CheckResult
	if err := json.Unmarshal(body, &releases); err != nil {
		t.Fatalf("decode releases: %v", err)
	}
	if releases.CurrentVersion != "v0.43-rc.4" || releases.LatestVersion != "v0.44" || !releases.UpdateAvailable || len(releases.Releases) != 1 {
		t.Fatalf("unexpected releases response: %+v", releases)
	}
	updateService.mu.Lock()
	checkCalls := updateService.checkCalls
	checkTimeout := updateService.checkTimeout
	updateService.mu.Unlock()
	if checkCalls != 1 || checkTimeout < 25*time.Second || checkTimeout > updateCheckTimeout {
		t.Fatalf("Check calls=%d timeout=%s, want one call with about 30s timeout", checkCalls, checkTimeout)
	}

	statusCode, body = performUpdateRequest(t, client, http.MethodGet, baseURL+"/api/update/status", nil, true, "")
	if statusCode != http.StatusOK {
		t.Fatalf("GET status = %d body=%q, want 200", statusCode, body)
	}
	var updateStatus updater.Status
	if err := json.Unmarshal(body, &updateStatus); err != nil {
		t.Fatalf("decode update status: %v", err)
	}
	if updateStatus.Phase != updater.PhaseDownloading || updateStatus.DownloadedBytes != 10 || updateStatus.TotalBytes != 100 {
		t.Fatalf("unexpected update status: %+v", updateStatus)
	}

	statusCode, body = performUpdateRequest(t, client, http.MethodPost, baseURL+"/api/update/install", []byte(`{"version":"v0.44"}`), true, "localhost:18080")
	if statusCode != http.StatusAccepted {
		t.Fatalf("POST install status = %d body=%q, want 202", statusCode, body)
	}
	if err := json.Unmarshal(body, &updateStatus); err != nil {
		t.Fatalf("decode install status: %v", err)
	}
	if updateStatus.Phase != updater.PhaseChecking || !updateStatus.Busy {
		t.Fatalf("unexpected install response: %+v", updateStatus)
	}
	updateService.mu.Lock()
	installCalls := updateService.installCalls
	installedVersion := updateService.installedVersion
	updateService.mu.Unlock()
	if installCalls != 1 || installedVersion != "v0.44" {
		t.Fatalf("StartInstall calls=%d version=%q", installCalls, installedVersion)
	}

	statusCode, body = performUpdateRequest(t, client, http.MethodGet, baseURL+"/api/health", nil, false, "")
	if statusCode != http.StatusOK {
		t.Fatalf("GET health status = %d body=%q", statusCode, body)
	}
	var health map[string]interface{}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	version, versionOK := health["version"].(string)
	pid, pidOK := health["pid"].(float64)
	if health["ok"] != true || !versionOK || version == "" || !pidOK || int(pid) != os.Getpid() || health["update_token"] != "handoff-token" {
		t.Fatalf("unexpected health response: %+v", health)
	}

	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/update/releases"},
		{method: http.MethodPost, path: "/api/update/status"},
		{method: http.MethodGet, path: "/api/update/install"},
	} {
		statusCode, body = performUpdateRequest(t, client, test.method, baseURL+test.path, nil, true, "")
		if statusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status=%d body=%q, want 405", test.method, test.path, statusCode, body)
		}
	}

	if srv.Updater != updateService {
		t.Fatal("server updater field changed unexpectedly")
	}
}

func TestConfigUpdateIsBlockedDuringApplicationUpdate(t *testing.T) {
	updateService := &fakeUpdater{status: updater.Status{Phase: updater.PhaseDownloading, Busy: true, Version: "v0.44"}}
	srv, baseURL, client := startUpdateTestServer(t, updateService)
	before := srv.Runtime.CurrentConfig()
	candidate := config.Clone(before)
	candidate.RetentionMinutes++
	body, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	statusCode, responseBody := performUpdateRequest(t, client, http.MethodPut, baseURL+"/api/config", body, true, "")
	if statusCode != http.StatusConflict || !strings.Contains(string(responseBody), "while an application update is running") {
		t.Fatalf("PUT config status=%d body=%q, want update conflict", statusCode, responseBody)
	}
	if after := srv.Runtime.CurrentConfig(); after.RetentionMinutes != before.RetentionMinutes || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("configuration changed during updater handoff: before=%+v after=%+v", before, after)
	}
}

func TestConfigUpdateAndInstallUseOneAdmissionGate(t *testing.T) {
	addr := freeHTTPAddr(t)
	runtime := &blockingConfigRuntime{
		fakeRuntime: newFakeRuntime(t, addr),
		started:     make(chan struct{}),
		proceed:     make(chan struct{}),
	}
	updateService := &observingInstallUpdater{
		fakeUpdater: &fakeUpdater{startStatus: updater.Status{Phase: updater.PhaseChecking, Busy: true, Version: "v0.44"}},
		started:     make(chan struct{}),
	}
	_, baseURL, client := startUpdateTestServerWithRuntime(t, addr, runtime, updateService)

	candidate := runtime.CurrentConfig()
	candidate.RetentionMinutes++
	body, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	configDone := make(chan updateRequestResult, 1)
	go func() {
		configDone <- executeUpdateRequest(client, http.MethodPut, baseURL+"/api/config", body, true, "localhost:18080")
	}()
	select {
	case <-runtime.started:
	case <-time.After(2 * time.Second):
		t.Fatal("configuration update did not enter the runtime")
	}

	installDone := make(chan updateRequestResult, 1)
	installHandlerStarted := make(chan struct{})
	go func() {
		close(installHandlerStarted)
		installDone <- executeUpdateRequest(client, http.MethodPost, baseURL+"/api/update/install", []byte(`{"version":"v0.44"}`), true, "localhost:18080")
	}()
	<-installHandlerStarted
	select {
	case <-updateService.started:
		t.Fatal("StartInstall entered while configuration mutation was still running")
	case <-time.After(150 * time.Millisecond):
	}

	close(runtime.proceed)
	select {
	case result := <-configDone:
		if result.err != nil || result.status != http.StatusOK {
			t.Fatalf("config PUT status=%d err=%v body=%q, want 200", result.status, result.err, result.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("configuration update did not finish")
	}
	select {
	case <-updateService.started:
	case <-time.After(2 * time.Second):
		t.Fatal("StartInstall did not proceed after configuration mutation finished")
	}
	select {
	case result := <-installDone:
		if result.err != nil || result.status != http.StatusAccepted {
			t.Fatalf("install POST status=%d err=%v body=%q, want 202", result.status, result.err, result.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("install request did not finish")
	}
}

func TestServerCloseCancelsUpdateCheck(t *testing.T) {
	updateService := &cancellationAwareUpdater{
		fakeUpdater: &fakeUpdater{},
		started:     make(chan struct{}),
		canceled:    make(chan struct{}),
	}
	srv, baseURL, client := startUpdateTestServer(t, updateService)
	requestDone := make(chan updateRequestResult, 1)
	go func() {
		requestDone <- executeUpdateRequest(client, http.MethodGet, baseURL+"/api/update/releases", nil, true, "localhost:18080")
	}()
	select {
	case <-updateService.started:
	case <-time.After(2 * time.Second):
		t.Fatal("update check did not start")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- srv.Close() }()
	select {
	case <-updateService.canceled:
	case <-time.After(time.Second):
		t.Fatal("Server.Close did not cancel the update check")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Server.Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Server.Close waited for the full update-check timeout")
	}
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled update request did not return")
	}
}

func TestUpdateInstallRejectsUntrustedAndInvalidRequests(t *testing.T) {
	updateService := &fakeUpdater{startStatus: updater.Status{Phase: updater.PhaseChecking, Busy: true}}
	_, baseURL, client := startUpdateTestServer(t, updateService)

	tests := []struct {
		name   string
		body   []byte
		marker bool
		host   string
		want   int
	}{
		{name: "missing marker", body: []byte(`{"version":"v0.44"}`), host: "localhost:18080", want: http.StatusForbidden},
		{name: "untrusted Host", body: []byte(`{"version":"v0.44"}`), marker: true, host: "pitchprox.attacker.example", want: http.StatusForbidden},
		{name: "empty", marker: true, host: "127.0.0.1:18080", want: http.StatusBadRequest},
		{name: "malformed", body: []byte(`{"version":`), marker: true, host: "127.0.0.1:18080", want: http.StatusBadRequest},
		{name: "unknown field", body: []byte(`{"version":"v0.44","extra":true}`), marker: true, host: "127.0.0.1:18080", want: http.StatusBadRequest},
		{name: "trailing value", body: []byte(`{"version":"v0.44"} {}`), marker: true, host: "127.0.0.1:18080", want: http.StatusBadRequest},
		{name: "missing version", body: []byte(`{}`), marker: true, host: "127.0.0.1:18080", want: http.StatusBadRequest},
		{name: "long version", body: []byte(`{"version":"` + strings.Repeat("v", maxUpdateVersionBytes+1) + `"}`), marker: true, host: "127.0.0.1:18080", want: http.StatusBadRequest},
		{name: "oversize", body: bytes.Repeat([]byte("x"), maxUpdateInstallBodyBytes+1), marker: true, host: "127.0.0.1:18080", want: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statusCode, body := performUpdateRequest(t, client, http.MethodPost, baseURL+"/api/update/install", test.body, test.marker, test.host)
			if statusCode != test.want {
				t.Fatalf("status=%d body=%q, want %d", statusCode, body, test.want)
			}
		})
	}
	updateService.mu.Lock()
	invalidCalls := updateService.installCalls
	updateService.mu.Unlock()
	if invalidCalls != 0 {
		t.Fatalf("invalid requests called StartInstall %d times", invalidCalls)
	}

	statusCode, body := performUpdateRequest(t, client, http.MethodPost, baseURL+"/api/update/install", []byte(" \n{\"version\":\" v0.44 \"}\n "), true, "[::1]:18080")
	if statusCode != http.StatusAccepted {
		t.Fatalf("trusted IPv6 Host status=%d body=%q, want 202", statusCode, body)
	}
	updateService.mu.Lock()
	defer updateService.mu.Unlock()
	if updateService.installCalls != 1 || updateService.installedVersion != "v0.44" {
		t.Fatalf("valid request calls=%d version=%q", updateService.installCalls, updateService.installedVersion)
	}
}

func TestUpdateEndpointsUnavailableWithoutUpdaterOrPausedWebUI(t *testing.T) {
	_, baseURL, client := startUpdateTestServer(t, nil)
	for _, path := range []string{"/api/update/releases", "/api/update/status"} {
		statusCode, body := performUpdateRequest(t, client, http.MethodGet, baseURL+path, nil, true, "")
		if statusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "updater is not available") {
			t.Errorf("GET %s status=%d body=%q, want clear 503", path, statusCode, body)
		}
	}
	statusCode, body := performUpdateRequest(t, client, http.MethodPost, baseURL+"/api/update/install", []byte(`{"version":"v0.44"}`), true, "localhost:18080")
	if statusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "updater is not available") {
		t.Fatalf("POST install without updater status=%d body=%q, want clear 503", statusCode, body)
	}
	statusCode, body = performUpdateRequest(t, client, http.MethodGet, baseURL+"/api/health", nil, false, "")
	if statusCode != http.StatusOK {
		t.Fatalf("health without updater status=%d body=%q", statusCode, body)
	}
	var health map[string]interface{}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("decode health without updater: %v", err)
	}
	if _, exists := health["update_token"]; exists {
		t.Fatalf("health unexpectedly exposed empty update_token: %+v", health)
	}
	pid, pidOK := health["pid"].(float64)
	if !pidOK || int(pid) != os.Getpid() {
		t.Fatalf("health pid=%v, want %d", health["pid"], os.Getpid())
	}

	pausedUpdater := &fakeUpdater{}
	pausedServer, pausedBaseURL, pausedClient := startUpdateTestServer(t, pausedUpdater)
	pausedServer.SetWebUIEnabled(false)
	for _, test := range []struct {
		method string
		path   string
		body   []byte
	}{
		{method: http.MethodGet, path: "/api/update/releases"},
		{method: http.MethodGet, path: "/api/update/status"},
		{method: http.MethodPost, path: "/api/update/install", body: []byte(`{"version":"v0.44"}`)},
	} {
		statusCode, responseBody := performUpdateRequest(t, pausedClient, test.method, pausedBaseURL+test.path, test.body, true, "localhost:18080")
		if statusCode != http.StatusServiceUnavailable || !strings.Contains(string(responseBody), "WebUI disabled") {
			t.Errorf("paused %s %s status=%d body=%q, want WebUI 503", test.method, test.path, statusCode, responseBody)
		}
		if isWebUIControlPath(test.path) {
			t.Errorf("update path %s was classified as a control path", test.path)
		}
	}
	statusCode, body = performUpdateRequest(t, pausedClient, http.MethodGet, pausedBaseURL+"/api/health", nil, false, "")
	if statusCode != http.StatusOK {
		t.Fatalf("paused health status=%d body=%q, want 200", statusCode, body)
	}
	health = nil
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("decode paused health: %v", err)
	}
	if _, exists := health["update_token"]; exists {
		t.Fatalf("health exposed update_token from updater with an empty token: %+v", health)
	}
	pausedUpdater.mu.Lock()
	defer pausedUpdater.mu.Unlock()
	if pausedUpdater.checkCalls != 0 || pausedUpdater.statusCalls != 0 || pausedUpdater.installCalls != 0 {
		t.Fatalf("paused WebUI reached updater: %+v", pausedUpdater)
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

func TestBrowserWebUIActivityClassification(t *testing.T) {
	markedHeaders := map[string]string{"x-pitchprox-webui": "1"}
	tests := []struct {
		name string
		req  request
		want bool
	}{
		{name: "static document", req: request{Method: "GET", Path: "/"}, want: true},
		{name: "static asset", req: request{Method: "GET", Path: "/app.js"}, want: true},
		{name: "unmarked API client", req: request{Method: "GET", Path: "/api/config"}, want: false},
		{name: "marked WebUI API", req: request{Method: "GET", Path: "/api/config", Headers: markedHeaders}, want: true},
		{name: "marked updater API", req: request{Method: "GET", Path: "/api/update/status", Headers: markedHeaders}, want: true},
		{name: "opened WebUI SSE", req: request{Method: "GET", Path: "/api/events", Query: url.Values{"_ui": {"1"}}}, want: true},
		{name: "control never counts", req: request{Method: "GET", Path: "/api/control/webui/status", Headers: markedHeaders}, want: false},
		{name: "tray never counts", req: request{Method: "GET", Path: "/api/tray", Headers: markedHeaders}, want: false},
		{name: "health never counts", req: request{Method: "GET", Path: "/api/health", Headers: markedHeaders}, want: false},
		{name: "visible tab", req: request{Method: "POST", Path: "/api/ui/visibility", Headers: markedHeaders, Body: []byte(`{"active":true}`)}, want: true},
		{name: "hidden tab", req: request{Method: "POST", Path: "/api/ui/visibility", Headers: markedHeaders, Body: []byte(`{"active":false}`)}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isBrowserWebUIActivity(test.req); got != test.want {
				t.Fatalf("isBrowserWebUIActivity() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestWebUIActivityFromAnyTabExtendsOneGlobalDeadline(t *testing.T) {
	runtime := newFakeRuntime(t, freeHTTPAddr(t))
	srv, err := New(runtime.cfg.HTTP.Listen, runtime, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.webUIIdleTimeout = time.Hour
	srv.webUILastBrowserRequest = time.Now().Add(-30 * time.Minute)
	srv.startWebUIIdleTimer()
	t.Cleanup(srv.stopWebUIIdleTimer)
	srv.webUIMu.RLock()
	initialTimer := srv.webUIIdleTimer
	srv.webUIMu.RUnlock()

	visible := request{Method: "POST", Path: "/api/ui/visibility", Headers: map[string]string{"x-pitchprox-webui": "1"}, Body: []byte(`{"active":true}`)}
	if !srv.admitWebUIRequest(visible) {
		t.Fatal("visible browser tab was not admitted")
	}
	first := srv.webUIStatus()
	if first.IdleDeadlineAt == nil {
		t.Fatal("visible browser tab did not establish an idle deadline")
	}

	hidden := visible
	hidden.Body = []byte(`{"active":false}`)
	if !srv.admitWebUIRequest(hidden) {
		t.Fatal("hidden browser tab request was not admitted")
	}
	afterHidden := srv.webUIStatus()
	if afterHidden.IdleDeadlineAt == nil || !afterHidden.IdleDeadlineAt.Equal(*first.IdleDeadlineAt) {
		t.Fatalf("hidden tab changed the shared deadline: before=%v after=%v", first.IdleDeadlineAt, afterHidden.IdleDeadlineAt)
	}

	time.Sleep(time.Millisecond)
	secondTab := request{Method: "GET", Path: "/api/config", Headers: map[string]string{"x-pitchprox-webui": "1"}}
	if !srv.admitWebUIRequest(secondTab) {
		t.Fatal("second browser tab was not admitted")
	}
	afterSecond := srv.webUIStatus()
	if afterSecond.IdleDeadlineAt == nil || !afterSecond.IdleDeadlineAt.After(*first.IdleDeadlineAt) {
		t.Fatalf("second tab did not extend the shared deadline: before=%v after=%v", first.IdleDeadlineAt, afterSecond.IdleDeadlineAt)
	}
	srv.webUIMu.RLock()
	afterRequestsTimer := srv.webUIIdleTimer
	srv.webUIMu.RUnlock()
	if initialTimer == nil || afterRequestsTimer != initialTimer {
		t.Fatal("ordinary browser requests churned the one-shot idle timer")
	}
}

func TestWebUIIdleTimerPausesOnlyUIAndNotifiesLongSSESubscriber(t *testing.T) {
	runtime := newFakeRuntime(t, freeHTTPAddr(t))
	srv, err := New(runtime.cfg.HTTP.Listen, runtime, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.webUIIdleTimeout = 40 * time.Millisecond
	_, events, cancel := runtime.mon.Subscribe()
	defer cancel()
	srv.startWebUIIdleTimer()
	t.Cleanup(srv.stopWebUIIdleTimer)

	deadline := time.After(2 * time.Second)
	var paused webUIStatusDTO
	for events != nil {
		select {
		case payload, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			var envelope struct {
				Type string          `json:"type"`
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(payload, &envelope); err != nil {
				t.Fatalf("decode transient event: %v", err)
			}
			if envelope.Type == "webui_status" {
				if err := json.Unmarshal(envelope.Data, &paused); err != nil {
					t.Fatalf("decode WebUI status event: %v", err)
				}
			}
		case <-deadline:
			t.Fatal("WebUI idle timer did not close the long-lived subscriber")
		}
	}

	if srv.WebUIEnabled() {
		t.Fatal("WebUI remained enabled after browser-idle timeout")
	}
	if !paused.AutoPaused || paused.DisabledReason != webUIDisabledIdle || paused.Paused {
		t.Fatalf("unexpected idle status event: %+v", paused)
	}
	if subscribers := runtime.mon.DiagnosticStats().Subscribers; subscribers != 0 {
		t.Fatalf("idle pause left %d live subscribers", subscribers)
	}
	if got := runtime.CurrentConfig().Rules[0].ID; got != "default" {
		t.Fatalf("idle pause unexpectedly changed runtime config: %q", got)
	}
}

func TestServerCloseWaitsForAndInvalidatesFiringWebUIIdleTimer(t *testing.T) {
	runtime := newFakeRuntime(t, freeHTTPAddr(t))
	srv, err := New(runtime.cfg.HTTP.Listen, runtime, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	srv.webUIIdleTimeout = time.Millisecond
	srv.webUIIdleCallbackHook = func() func() {
		close(callbackEntered)
		<-releaseCallback
		return nil
	}
	_, events, cancel := runtime.mon.Subscribe()
	defer cancel()
	srv.startWebUIIdleTimer()

	select {
	case <-callbackEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("idle callback did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- srv.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before firing idle callback exited: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(releaseCallback)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after idle callback exited")
	}
	if !srv.WebUIEnabled() {
		t.Fatal("stale idle callback disabled WebUI during Close")
	}
	select {
	case payload := <-events:
		t.Fatalf("stale idle callback published after Close began: %s", payload)
	default:
	}
}

func TestFiringIdleTimerCannotUndoManualDisableThenEnable(t *testing.T) {
	runtime := newFakeRuntime(t, freeHTTPAddr(t))
	srv, err := New(runtime.cfg.HTTP.Listen, runtime, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	callbackDone := make(chan struct{})
	srv.webUIIdleTimeout = time.Millisecond
	srv.webUIIdleCallbackHook = func() func() {
		close(callbackEntered)
		<-releaseCallback
		return func() { close(callbackDone) }
	}
	srv.startWebUIIdleTimer()

	select {
	case <-callbackEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("idle callback did not start")
	}
	srv.SetWebUIEnabled(false)
	srv.webUIMu.Lock()
	srv.webUIIdleTimeout = time.Hour
	srv.webUIIdleCallbackHook = nil
	srv.webUIMu.Unlock()
	srv.SetWebUIEnabled(true)
	close(releaseCallback)
	select {
	case <-callbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("stale idle callback did not exit")
	}
	t.Cleanup(srv.stopWebUIIdleTimer)

	status := srv.webUIStatus()
	if !status.Enabled || status.AutoPaused || status.DisabledReason != "" || status.IdleDeadlineAt == nil {
		t.Fatalf("stale idle callback undid the manual re-enable: %+v", status)
	}
	if until := time.Until(*status.IdleDeadlineAt); until < 59*time.Minute {
		t.Fatalf("manual re-enable did not establish a fresh one-hour deadline: %v", until)
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

func TestRuleConditionActivityEndpointReturnsBoundedObservedTuples(t *testing.T) {
	addr := freeHTTPAddr(t)
	runtime := newFakeRuntime(t, addr)
	runtime.mon.AddRuleConditionConnection("Rule-ID", "Rule", config.ActionProxy, monitor.RuleConditionMatch{
		Application: "chrome.exe", Host: "*.example.com", Port: "443", Source: monitor.RuleConditionSourceIntercepted,
	})
	runtime.mon.AddRuleConditionConnection("Rule-ID", "Rule", config.ActionProxy, monitor.RuleConditionMatch{
		Application: "chrome.exe", Host: "*.example.com", Port: "443", Source: monitor.RuleConditionSourceDirectObserver,
	})
	runtime.mon.AddRuleConditionConnection("rule-id", "Other exact ID", config.ActionProxy, monitor.RuleConditionMatch{
		Application: "other.exe", Host: "Any", Port: "Any", Source: monitor.RuleConditionSourceIntercepted,
	})

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
	resp, err := client.Get("http://" + addr + "/api/rules/condition-activity?id=Rule-ID&window_minutes=5&limit=10")
	if err != nil {
		t.Fatalf("GET condition activity: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET condition activity status = %d, want 200", resp.StatusCode)
	}
	var result monitor.RuleConditionActivity
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode condition activity: %v", err)
	}
	if result.RuleID != "Rule-ID" || result.TotalHits != 2 || len(result.Conditions) != 1 {
		t.Fatalf("condition result = %+v", result)
	}
	condition := result.Conditions[0]
	if condition.Application != "chrome.exe" || condition.Host != "*.example.com" || condition.Port != "443" || condition.Hits != 2 || condition.Share != 1 {
		t.Fatalf("condition = %+v", condition)
	}
	if result.SourceHits.Intercepted != 1 || result.SourceHits.DirectObserver != 1 || result.Accuracy.DirectComplete {
		t.Fatalf("accuracy/source metadata = %+v / %+v", result.SourceHits, result.Accuracy)
	}
	if apps := result.Dimensions.Applications; apps.TotalHits != 2 || apps.Truncated || len(apps.Values) != 1 || apps.Values[0].Hits != 2 {
		t.Fatalf("application dimension = %+v", apps)
	}

	for _, path := range []string{
		"/api/rules/condition-activity",
		"/api/rules/condition-activity?id=a&id=b",
		"/api/rules/condition-activity?id=Rule-ID&limit=101",
		"/api/rules/condition-activity?id=Rule-ID&window_minutes=0",
	} {
		resp, err := client.Get("http://" + addr + path)
		if err != nil {
			t.Fatalf("GET invalid condition activity: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET %s status = %d, want 400", path, resp.StatusCode)
		}
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

func TestControlRequestsDoNotPreventAutomaticWebUIPause(t *testing.T) {
	addr := freeHTTPAddr(t)
	runtime := newFakeRuntime(t, addr)
	srv, err := New(addr, runtime, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.webUIIdleTimeout = 80 * time.Millisecond
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
	deadline := time.Now().Add(2 * time.Second)
	var status webUIStatusDTO
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/api/control/webui/status")
		if err != nil {
			t.Fatalf("GET WebUI status: %v", err)
		}
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			_ = resp.Body.Close()
			t.Fatalf("decode WebUI status: %v", err)
		}
		_ = resp.Body.Close()
		if !status.Enabled {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status.Enabled || !status.AutoPaused || status.DisabledReason != webUIDisabledIdle {
		t.Fatalf("control polling kept WebUI alive or returned wrong status: %+v", status)
	}
	if status.Paused {
		t.Fatal("automatic WebUI pause was reported as a proxy-service pause")
	}

	resp, err := client.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET disabled WebUI page: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read disabled WebUI page: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "автоматически приостановлен") || !strings.Contains(string(body), "Проксирование продолжает работать") {
		t.Fatalf("unexpected disabled WebUI page status=%d body=%q", resp.StatusCode, body)
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

func startUpdateTestServer(t *testing.T, updateService Updater) (*Server, string, *http.Client) {
	t.Helper()
	addr := freeHTTPAddr(t)
	return startUpdateTestServerWithRuntime(t, addr, newFakeRuntime(t, addr), updateService)
}

func startUpdateTestServerWithRuntime(t *testing.T, addr string, runtime Runtime, updateService Updater) (*Server, string, *http.Client) {
	t.Helper()
	srv, err := New(addr, runtime, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.SetUpdater(updateService)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case err := <-done:
			if err != nil && err != ErrClosed {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not return after Close")
		}
	})
	client := &http.Client{Timeout: 2 * time.Second}
	return srv, "http://" + addr, client
}

type updateRequestResult struct {
	status int
	body   []byte
	err    error
}

func executeUpdateRequest(client *http.Client, method, target string, body []byte, marked bool, host string) updateRequestResult {
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return updateRequestResult{err: err}
	}
	if marked {
		req.Header.Set("X-PitchProx-WebUI", "1")
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		return updateRequestResult{err: err}
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	return updateRequestResult{status: resp.StatusCode, body: responseBody, err: err}
}

func performUpdateRequest(t *testing.T, client *http.Client, method, target string, body []byte, marked bool, host string) (int, []byte) {
	t.Helper()
	result := executeUpdateRequest(client, method, target, body, marked, host)
	if result.err != nil {
		t.Fatalf("%s %s: %v", method, target, result.err)
	}
	return result.status, result.body
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
