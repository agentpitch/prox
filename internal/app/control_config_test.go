package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/control"
	"github.com/agentpitch/prox/internal/httpapi"
)

func startControlTestProgram(t *testing.T) (*Program, string) {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	prog, err := NewProgram(path, filepath.Join(tmp, "history"))
	if err != nil {
		t.Fatal(err)
	}
	cleanupBeforeTempDir(t, tmp, prog.Stop)
	cfg := runtimeTestConfig()
	cfg.HTTP.Listen = freeTCPAddr(t)
	if err := prog.Runtime().UpdateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := prog.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return prog, path
}

func requireControlError(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr *control.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != code {
		t.Fatalf("error = %v, want API error %q", err, code)
	}
}

func TestControlConfigPreviewAndNoopDoNotMutate(t *testing.T) {
	prog, path := startControlTestProgram(t)
	if err := prog.DisableWebUI(); err != nil {
		t.Fatal(err)
	}
	before := prog.Runtime().CurrentConfig()
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	candidate := config.Clone(before)
	candidate.HTTP.Listen = freeTCPAddr(t)
	candidate.Transparent.SniffBytes++
	preview, err := prog.ApplyControlConfig(control.ConfigRequest{Config: candidate, DryRun: true})
	if err != nil || preview.Applied || !preview.Plan.HTTPRebind || !preview.Plan.RuntimeRestart {
		t.Fatalf("preview = %+v, %v", preview, err)
	}
	// A preview must not even reserve the proposed endpoint.
	reserved, err := net.Listen("tcp", candidate.HTTP.Listen)
	if err != nil {
		t.Fatalf("preview bound the proposed listener: %v", err)
	}
	_ = reserved.Close()
	noop, err := prog.ApplyControlConfig(control.ConfigRequest{Config: before, ExpectedUpdatedAt: before.UpdatedAt})
	if err != nil || noop.Applied || noop.Plan.Mode != "no_change" || !noop.Config.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("no-op = %+v, %v", noop, err)
	}
	afterDisk, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(disk, afterDisk) {
		t.Fatalf("preview/no-op changed saved config: %v", err)
	}
	if prog.WebUIRunning() || prog.Runtime().Monitor().UIActive() {
		t.Fatal("headless preview/no-op activated WebUI monitoring")
	}
}

func TestControlConfigHotReloadPreservesRuntimeAndRequiresRevision(t *testing.T) {
	prog, _ := startControlTestProgram(t)
	if err := prog.DisableWebUI(); err != nil {
		t.Fatal(err)
	}
	before := prog.Runtime().CurrentConfig()
	candidate := config.Clone(before)
	candidate.Rules[0].Name = "Updated rule"
	candidate.Proxies[0].Address = "127.0.0.1:8999"
	_, err := prog.ApplyControlConfig(control.ConfigRequest{Config: candidate})
	requireControlError(t, err, "revision_required")
	flows, observer := prog.runtime.flows, prog.runtime.directObserver
	result, err := prog.ApplyControlConfig(control.ConfigRequest{Config: candidate, ExpectedUpdatedAt: before.UpdatedAt})
	if err != nil || !result.Applied || result.Plan.Mode != "hot_reload" || !result.Plan.ConnectionsPreserved {
		t.Fatalf("hot reload = %+v, %v", result, err)
	}
	if prog.runtime.flows != flows || prog.runtime.directObserver != observer || !prog.Runtime().Running() {
		t.Fatal("hot reload restarted routing/observer")
	}
	if prog.WebUIRunning() || prog.Runtime().Monitor().UIActive() {
		t.Fatal("headless apply activated WebUI monitoring")
	}
	if result.Config.Rules[0].Name != "Updated rule" || !result.Config.UpdatedAt.After(before.UpdatedAt) {
		t.Fatal("hot reload did not activate the new config revision")
	}
	_, err = prog.ApplyControlConfig(control.ConfigRequest{Config: before, ExpectedUpdatedAt: before.UpdatedAt})
	requireControlError(t, err, "revision_conflict")
}

func TestControlConfigDisruptiveApplyRequiresExplicitOptIn(t *testing.T) {
	prog, _ := startControlTestProgram(t)
	before := prog.Runtime().CurrentConfig()
	candidate := config.Clone(before)
	candidate.Transparent.SniffBytes++
	flows := prog.runtime.flows
	result, err := prog.ApplyControlConfig(control.ConfigRequest{Config: candidate, ExpectedUpdatedAt: before.UpdatedAt})
	requireControlError(t, err, "disruptive_change")
	if !result.Plan.RuntimeRestart || result.Plan.ConnectionsPreserved || prog.runtime.flows != flows || !prog.Runtime().CurrentConfig().UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatal("rejected disruptive apply changed runtime or lacked impact plan")
	}
	result, err = prog.ApplyControlConfig(control.ConfigRequest{Config: candidate, ExpectedUpdatedAt: before.UpdatedAt, AllowDisruptive: true})
	if err != nil || !result.Applied || prog.runtime.flows == flows || !prog.Runtime().Running() {
		t.Fatalf("explicit disruptive apply = %+v, %v", result, err)
	}
}

func TestControlConfigRebindReturnsResponseAndPreservesPausedUIState(t *testing.T) {
	for _, state := range []string{"ui_enabled", "ui_disabled", "paused"} {
		t.Run(state, func(t *testing.T) {
			prog, _ := startControlTestProgram(t)
			paused := state == "paused"
			uiEnabled := state == "ui_enabled"
			if paused {
				if err := prog.PauseService(); err != nil {
					t.Fatal(err)
				}
			} else if !uiEnabled {
				if err := prog.DisableWebUI(); err != nil {
					t.Fatal(err)
				}
			} else {
				prog.Runtime().Monitor().MarkUIActive()
			}
			before := prog.Runtime().CurrentConfig()
			candidate := config.Clone(before)
			candidate.HTTP.Listen = freeTCPAddr(t)
			if paused {
				candidate.Transparent.SniffBytes++
			}
			flows, observer := prog.runtime.flows, prog.runtime.directObserver
			body, _ := json.Marshal(control.ConfigRequest{Config: candidate, ExpectedUpdatedAt: before.UpdatedAt})
			req, _ := http.NewRequest(http.MethodPut, "http://"+before.HTTP.Listen+"/api/control/agent/config", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-PitchProx-Agent", "1")
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("old listener did not finish apply response: %v", err)
			}
			defer resp.Body.Close()
			var result control.ConfigResult
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || resp.StatusCode != http.StatusOK || !result.Applied {
				t.Fatalf("apply response status=%d result=%+v error=%v", resp.StatusCode, result, err)
			}
			waitHTTPHealth(t, candidate.HTTP.Listen)
			if prog.ServicePaused() != paused || prog.WebUIRunning() != uiEnabled || prog.Runtime().Running() == paused || prog.Runtime().Monitor().UIActive() != uiEnabled {
				t.Fatal("HTTP rebind changed paused/UI state")
			}
			if prog.runtime.flows != flows || prog.runtime.directObserver != observer {
				t.Fatal("HTTP rebind replaced the routing runtime")
			}
		})
	}
}

func TestControlConfigRebindRollsBackOnFailure(t *testing.T) {
	for _, failure := range []string{"busy_listener", "save", "runtime"} {
		t.Run(failure, func(t *testing.T) {
			prog, path := startControlTestProgram(t)
			before := prog.Runtime().CurrentConfig()
			candidate := config.Clone(before)
			candidate.HTTP.Listen = freeTCPAddr(t)
			candidate.Rules[0].Name = "Must not persist"
			if failure == "busy_listener" {
				ln, err := net.Listen("tcp", candidate.HTTP.Listen)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
			}
			if failure == "save" {
				if err := os.Mkdir(path+".tmp", 0o700); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(path + ".tmp")
			}
			if failure == "runtime" {
				candidate.Transparent.IPv4Listener = "203.0.113.123"
				candidate.Rules[0].Action = config.ActionProxy
				candidate.Rules[0].ProxyID = "p1"
			}
			disk, _ := os.ReadFile(path)
			_, err := prog.ApplyControlConfig(control.ConfigRequest{Config: candidate, ExpectedUpdatedAt: before.UpdatedAt, AllowDisruptive: true})
			requireControlError(t, err, "activation_failed")
			after := prog.Runtime().CurrentConfig()
			afterDisk, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(disk, afterDisk) || !after.UpdatedAt.Equal(before.UpdatedAt) || after.HTTP.Listen != before.HTTP.Listen || after.Rules[0].Name != before.Rules[0].Name {
				t.Fatal("failed apply did not retain the old saved/runtime configuration")
			}
			waitHTTPHealth(t, before.HTTP.Listen)
			if !prog.Runtime().Running() {
				t.Fatal("failed apply left the old runtime stopped")
			}
			if failure != "busy_listener" {
				ln, err := net.Listen("tcp", candidate.HTTP.Listen)
				if err != nil {
					t.Fatalf("failed apply leaked the replacement listener: %v", err)
				}
				_ = ln.Close()
			}
		})
	}
}

func TestWebUIControlAcceptedBeforeHandoffUpdatesCurrentListener(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disable"
		if enabled {
			name = "enable"
		}
		t.Run(name, func(t *testing.T) {
			prog, _ := startControlTestProgram(t)
			if enabled {
				if err := prog.DisableWebUI(); err != nil {
					t.Fatal(err)
				}
			}
			before := prog.Runtime().CurrentConfig()
			prog.httpMu.Lock()
			oldHTTP := prog.http
			prog.httpMu.Unlock()
			entered := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			controlUI := oldHTTP.WebUIControlFunc
			oldHTTP.WebUIControlFunc = func(want bool) (httpapi.WebUIStatus, error) {
				close(entered)
				<-release
				return controlUI(want)
			}
			type reply struct {
				status httpapi.WebUIStatus
				err    error
			}
			done := make(chan reply, 1)
			go func() {
				client := &http.Client{Timeout: 3 * time.Second}
				resp, err := client.Post("http://"+before.HTTP.Listen+"/api/control/webui/"+name, "application/json", bytes.NewReader([]byte("{}")))
				var status httpapi.WebUIStatus
				if err == nil {
					err = json.NewDecoder(resp.Body).Decode(&status)
					_ = resp.Body.Close()
				}
				done <- reply{status, err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("old listener did not accept UI control")
			}
			candidate := config.Clone(before)
			candidate.HTTP.Listen = freeTCPAddr(t)
			if _, err := prog.ApplyControlConfig(control.ConfigRequest{Config: candidate, ExpectedUpdatedAt: before.UpdatedAt}); err != nil {
				t.Fatal(err)
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case response := <-done:
				if response.err != nil || response.status.Enabled != enabled {
					t.Fatalf("retiring listener returned stale UI status: %+v, %v", response.status, response.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("UI control deadlocked against listener retirement")
			}
			if prog.WebUIRunning() != enabled {
				t.Fatalf("%s accepted by old listener was lost during handoff", name)
			}
			if !enabled && prog.Runtime().Monitor().UIActive() {
				t.Fatal("disable left WebUI monitoring active")
			}
		})
	}
}

func TestControlConfigConcurrentWritersCannotOverwriteRevision(t *testing.T) {
	prog, _ := startControlTestProgram(t)
	before := prog.Runtime().CurrentConfig()
	start := make(chan struct{})
	errorsCh := make(chan error, 2)
	var wg sync.WaitGroup
	for _, name := range []string{"First", "Second"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			candidate := config.Clone(before)
			candidate.Rules[0].Name = name
			<-start
			_, err := prog.ApplyControlConfig(control.ConfigRequest{Config: candidate, ExpectedUpdatedAt: before.UpdatedAt})
			errorsCh <- err
		}(name)
	}
	close(start)
	wg.Wait()
	err1, err2 := <-errorsCh, <-errorsCh
	if err1 == nil && err2 != nil {
		requireControlError(t, err2, "revision_conflict")
	} else if err2 == nil && err1 != nil {
		requireControlError(t, err1, "revision_conflict")
	} else {
		t.Fatalf("concurrent writers = %v, %v; want one success and one conflict", err1, err2)
	}
}
