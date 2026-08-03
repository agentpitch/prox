package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/win"
)

func runtimeTestConfig() config.Config {
	return config.Config{
		HTTP:        config.HTTPConfig{Listen: "127.0.0.1:18080"},
		Transparent: config.TransparentConfig{IPv4Listener: "0.0.0.0", IPv6Listener: "::", ListenerPort: 26001, SniffBytes: 4096, SniffTimeout: 1500},
		Proxies: []config.ProxyProfile{{
			ID:      "p1",
			Name:    "Primary",
			Type:    "http",
			Address: "127.0.0.1:8080",
			Enabled: true,
		}},
		Rules: []config.Rule{{
			ID:           "default",
			Name:         "Default",
			Enabled:      true,
			Applications: "*",
			TargetHosts:  "Any",
			TargetPorts:  "Any",
			Action:       config.ActionDirect,
		}},
	}
}

func cleanupRuntimeBeforeTempDir(t *testing.T, rt *Runtime, tempDir string) {
	cleanupBeforeTempDir(t, tempDir, rt.Stop)
}

func cleanupBeforeTempDir(t *testing.T, tempDir string, stop func() error) {
	t.Helper()
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("stop test runtime: %v", err)
		}
		// On Windows, testing.TempDir can race the final filesystem metadata
		// update after history files are closed and report a transient
		// "directory is not empty". Remove the child directory before the
		// testing package removes its parent, while still failing if it cannot
		// be released promptly.
		deadline := time.Now().Add(500 * time.Millisecond)
		for {
			err := os.RemoveAll(tempDir)
			if err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("remove runtime temp dir: %v", err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func TestRuntimeUpdateConfigStoresCanonicalCopy(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.json")
	historyPath := filepath.Join(tmp, "history")

	rt, err := NewRuntime(cfgPath, historyPath)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	cleanupRuntimeBeforeTempDir(t, rt, tmp)

	before := rt.CurrentConfig().UpdatedAt
	cfg := runtimeTestConfig()
	cfg.HTTP.Listen = " 127.0.0.1:19090 "
	cfg.Proxies[0].ID = " p1 "
	cfg.Proxies[0].Name = " Primary "
	cfg.Proxies[0].Type = "HTTP CONNECT"
	cfg.Proxies[0].Address = " 127.0.0.1:8080 "
	cfg.Rules = []config.Rule{{
		ID:           " r1 ",
		Name:         " Proxy all ",
		Enabled:      true,
		Applications: " * ",
		TargetHosts:  " Any ",
		TargetPorts:  " 443 ",
		Action:       config.RuleAction(" PROXY "),
		ProxyID:      " p1 ",
		ChainID:      " should-clear ",
	}}

	if err := rt.UpdateConfig(cfg); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	got := rt.CurrentConfig()
	if got.HTTP.Listen != "127.0.0.1:19090" {
		t.Fatalf("listen not normalized: %q", got.HTTP.Listen)
	}
	if got.Proxies[0].ID != "p1" || got.Proxies[0].Name != "Primary" || got.Proxies[0].Type != "http" || got.Proxies[0].Address != "127.0.0.1:8080" {
		t.Fatalf("proxy not canonicalized: %+v", got.Proxies[0])
	}
	if got.Rules[0].ID != "r1" || got.Rules[0].Name != "Proxy all" {
		t.Fatalf("rule metadata not canonicalized: %+v", got.Rules[0])
	}
	if got.Rules[0].Action != config.ActionProxy || got.Rules[0].ProxyID != "p1" || got.Rules[0].ChainID != "" {
		t.Fatalf("rule routing not canonicalized: %+v", got.Rules[0])
	}
	if got.UpdatedAt.IsZero() || (!before.IsZero() && got.UpdatedAt.Before(before)) {
		t.Fatalf("updated_at was not refreshed: before=%v after=%v", before, got.UpdatedAt)
	}

	got.Proxies[0].Name = "mutated"
	fresh := rt.CurrentConfig()
	if fresh.Proxies[0].Name != "Primary" {
		t.Fatalf("CurrentConfig leaked mutable state: %+v", fresh.Proxies[0])
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	var onDisk config.Config
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("unmarshal on-disk config: %v", err)
	}
	if onDisk.HTTP.Listen != got.HTTP.Listen || onDisk.Rules[0].Action != got.Rules[0].Action || onDisk.Proxies[0].ID != got.Proxies[0].ID {
		t.Fatalf("disk config differs from runtime copy: disk=%+v runtime=%+v", onDisk, got)
	}
}

func TestRuntimeUpdateConfigRejectsUnsupportedAction(t *testing.T) {
	tmp := t.TempDir()
	rt, err := NewRuntime(filepath.Join(tmp, "config.json"), filepath.Join(tmp, "history"))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	cleanupRuntimeBeforeTempDir(t, rt, tmp)

	cfg := runtimeTestConfig()
	cfg.Rules[0] = config.Rule{
		ID:           "r1",
		Name:         "Broken",
		Enabled:      true,
		Applications: "*",
		TargetHosts:  "Any",
		TargetPorts:  "Any",
		Action:       config.RuleAction("BROKN"),
	}
	if err := rt.UpdateConfig(cfg); err == nil {
		t.Fatal("expected unsupported action error")
	}
}

func TestRuntimeUpdateConfigRefreshesUpdatedAt(t *testing.T) {
	tmp := t.TempDir()
	rt, err := NewRuntime(filepath.Join(tmp, "config.json"), filepath.Join(tmp, "history"))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	cleanupRuntimeBeforeTempDir(t, rt, tmp)

	cfg := runtimeTestConfig()
	if err := rt.UpdateConfig(cfg); err != nil {
		t.Fatalf("first update: %v", err)
	}
	first := rt.CurrentConfig().UpdatedAt
	time.Sleep(10 * time.Millisecond)
	cfg.HTTP.Listen = "127.0.0.1:18081"
	if err := rt.UpdateConfig(cfg); err != nil {
		t.Fatalf("second update: %v", err)
	}
	second := rt.CurrentConfig().UpdatedAt
	if !second.After(first) {
		t.Fatalf("updated_at did not advance: first=%v second=%v", first, second)
	}
}

func TestRuntimeUpdateConfigIfCurrentRejectsStaleVersionAndAllowsLegacyZero(t *testing.T) {
	tmp := t.TempDir()
	rt, err := NewRuntime(filepath.Join(tmp, "config.json"), filepath.Join(tmp, "history"))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	cleanupRuntimeBeforeTempDir(t, rt, tmp)

	initial := rt.CurrentConfig()
	first := config.Clone(initial)
	first.RetentionMinutes = 8
	if err := rt.UpdateConfigIfCurrent(first, initial.UpdatedAt); err != nil {
		t.Fatalf("matching update: %v", err)
	}
	saved := rt.CurrentConfig()
	if !saved.UpdatedAt.After(initial.UpdatedAt) {
		t.Fatalf("updated_at did not advance: initial=%v saved=%v", initial.UpdatedAt, saved.UpdatedAt)
	}

	stale := config.Clone(initial)
	stale.RetentionMinutes = 9
	err = rt.UpdateConfigIfCurrent(stale, initial.UpdatedAt)
	if !errors.Is(err, config.ErrConfigConflict) {
		t.Fatalf("stale update error = %v, want ErrConfigConflict", err)
	}
	afterConflict := rt.CurrentConfig()
	if afterConflict.RetentionMinutes != saved.RetentionMinutes || !afterConflict.UpdatedAt.Equal(saved.UpdatedAt) {
		t.Fatalf("stale update changed config: before=%+v after=%+v", saved, afterConflict)
	}

	legacy := config.Clone(afterConflict)
	legacy.UpdatedAt = time.Time{}
	legacy.RetentionMinutes = 10
	if err := rt.UpdateConfigIfCurrent(legacy, time.Time{}); err != nil {
		t.Fatalf("legacy zero-timestamp update: %v", err)
	}
	if got := rt.CurrentConfig(); got.RetentionMinutes != 10 || !got.UpdatedAt.After(afterConflict.UpdatedAt) {
		t.Fatalf("legacy update was not saved: before=%+v after=%+v", afterConflict, got)
	}
}

func TestRuntimeUpdateConfigIfCurrentAllowsOnlyOneConcurrentWriter(t *testing.T) {
	tmp := t.TempDir()
	rt, err := NewRuntime(filepath.Join(tmp, "config.json"), filepath.Join(tmp, "history"))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	cleanupRuntimeBeforeTempDir(t, rt, tmp)

	initial := rt.CurrentConfig()
	first := config.Clone(initial)
	first.RetentionMinutes = 8
	second := config.Clone(initial)
	second.RetentionMinutes = 9

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, candidate := range []config.Config{first, second} {
		candidate := candidate
		go func() {
			<-start
			results <- rt.UpdateConfigIfCurrent(candidate, initial.UpdatedAt)
		}()
	}
	close(start)

	succeeded := 0
	conflicted := 0
	for i := 0; i < 2; i++ {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, config.ErrConfigConflict):
			conflicted++
		default:
			t.Fatalf("concurrent update returned unexpected error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent results: succeeded=%d conflicted=%d, want 1 and 1", succeeded, conflicted)
	}
	if got := rt.CurrentConfig().RetentionMinutes; got != 8 && got != 9 {
		t.Fatalf("saved retention = %d, want 8 or 9", got)
	}
}

func TestRuntimeStartWaitsForConfigTransition(t *testing.T) {
	tmp := t.TempDir()
	rt, err := NewRuntime(filepath.Join(tmp, "config.json"), filepath.Join(tmp, "history"))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	cleanupRuntimeBeforeTempDir(t, rt, tmp)

	initial := rt.CurrentConfig()
	candidate := config.Clone(initial)
	candidate.Transparent.SniffBytes++

	transitionEntered := make(chan struct{})
	releaseTransition := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseTransition) }) })
	updateDone := make(chan error, 1)
	go func() {
		rt.transitionMu.Lock()
		close(transitionEntered)
		<-releaseTransition
		err := rt.updateConfigIfCurrentTransitionLocked(candidate, initial.UpdatedAt)
		rt.transitionMu.Unlock()
		updateDone <- err
	}()

	select {
	case <-transitionEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("config transition did not acquire the transition lock")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCalled := make(chan struct{})
	startDone := make(chan error, 1)
	go func() {
		close(startCalled)
		startDone <- rt.Start(ctx)
	}()
	<-startCalled
	select {
	case err := <-startDone:
		t.Fatalf("Start bypassed the in-flight config transition: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(releaseTransition) })
	if err := <-updateDone; err != nil {
		t.Fatalf("config transition: %v", err)
	}
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start after config transition: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not continue after the config transition completed")
	}
	if got := rt.CurrentConfig().Transparent.SniffBytes; got != candidate.Transparent.SniffBytes {
		t.Fatalf("runtime started without the committed config: sniff_bytes=%d want=%d", got, candidate.Transparent.SniffBytes)
	}
	if !rt.Running() {
		t.Fatal("runtime is not running after the serialized transition")
	}
}

func TestRuntimeUpdateConfigRestartsRunningObserverModeForTransparentChange(t *testing.T) {
	tmp := t.TempDir()
	rt, err := NewRuntime(filepath.Join(tmp, "config.json"), filepath.Join(tmp, "history"))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	cleanupRuntimeBeforeTempDir(t, rt, tmp)

	cfg := runtimeTestConfig()
	if err := rt.UpdateConfig(cfg); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	rt.runMu.RLock()
	oldFlows := rt.flows
	rt.runMu.RUnlock()

	cfg.Transparent.SniffBytes++
	if err := rt.UpdateConfig(cfg); err != nil {
		t.Fatalf("UpdateConfig with transparent change: %v", err)
	}
	if !rt.Running() {
		t.Fatal("runtime is not running after transparent config restart")
	}
	rt.runMu.RLock()
	newFlows := rt.flows
	rt.runMu.RUnlock()
	if newFlows == nil || newFlows == oldFlows {
		t.Fatal("runtime restart did not replace flow table")
	}
}

func TestRuntimeUpdateConfigRollsBackWhenRestartFails(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.json")
	rt, err := NewRuntime(cfgPath, filepath.Join(tmp, "history"))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	cleanupRuntimeBeforeTempDir(t, rt, tmp)

	oldCfg := runtimeTestConfig()
	if err := rt.UpdateConfig(oldCfg); err != nil {
		t.Fatalf("initial UpdateConfig: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	broken := config.Clone(oldCfg)
	broken.Transparent.IPv4Listener = "203.0.113.123"
	broken.Rules[0].Action = config.ActionProxy
	broken.Rules[0].ProxyID = "p1"
	if err := rt.UpdateConfig(broken); err == nil {
		t.Fatal("UpdateConfig succeeded with an unavailable transparent listener address")
	}
	if !rt.Running() {
		t.Fatal("runtime was not restarted with the previous configuration")
	}
	got := rt.CurrentConfig()
	if got.Transparent.IPv4Listener != oldCfg.Transparent.IPv4Listener || got.Rules[0].Action != config.ActionDirect {
		t.Fatalf("runtime config was not rolled back: %+v", got)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var onDisk config.Config
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if onDisk.Transparent.IPv4Listener != oldCfg.Transparent.IPv4Listener || onDisk.Rules[0].Action != config.ActionDirect {
		t.Fatalf("on-disk config was not preserved: %+v", onDisk)
	}
}

func TestRuntimePauseWaitsForRunGoroutines(t *testing.T) {
	tmp := t.TempDir()
	rt, err := NewRuntime(filepath.Join(tmp, "config.json"), filepath.Join(tmp, "history"))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	cleanupRuntimeBeforeTempDir(t, rt, tmp)

	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	rt.listTCPConnections = func() ([]win.TCPConnection, error) {
		enteredOnce.Do(func() { close(entered) })
		<-release
		return nil, nil
	}
	rt.monitor.MarkUIActive()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not enter TCP scan")
	}

	done := make(chan error, 1)
	go func() { done <- rt.Pause() }()
	select {
	case err := <-done:
		t.Fatalf("Pause returned before observer goroutine exited: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Pause: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Pause did not finish after observer scan was released")
	}
}
