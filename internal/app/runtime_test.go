package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openai/pitchprox/internal/config"
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

func TestRuntimeUpdateConfigStoresCanonicalCopy(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.json")
	historyPath := filepath.Join(tmp, "history")

	rt, err := NewRuntime(cfgPath, historyPath)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer func() {
		_ = rt.Stop()
	}()

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
	defer func() { _ = rt.Stop() }()

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
	defer func() { _ = rt.Stop() }()

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
