package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreEstablishesAndPersistsMissingRevisionOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := DefaultConfig()
	cfg.UpdatedAt = time.Time{}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	revision := first.Get().UpdatedAt
	if revision.IsZero() {
		t.Fatal("legacy configuration has no usable revision")
	}
	second, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.Get().UpdatedAt != revision {
		t.Fatal("loading an existing revision changed it")
	}
}

func TestConfigRejectsUndiscoverableHTTPPorts(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:0", "localhost:http", "[::1]:65536", "127.0.0.1:-1", "127.0.0.1:"} {
		cfg := DefaultConfig()
		cfg.HTTP.Listen = listen
		if _, err := Canonicalize(cfg); err == nil {
			t.Errorf("accepted HTTP listener %q", listen)
		}
	}
}

func TestStoreLoadsUTF8BOMConfig(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	cfg, err := Canonicalize(DefaultConfig())
	if err != nil {
		t.Fatalf("Canonicalize default: %v", err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal config: %v", err)
	}
	data = append([]byte{0xEF, 0xBB, 0xBF}, data...)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("Write config: %v", err)
	}

	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if got := store.Get().HTTP.Listen; got != cfg.HTTP.Listen {
		t.Fatalf("listen = %q, want %q", got, cfg.HTTP.Listen)
	}
}

func TestStoreSaveAlwaysAdvancesUpdatedAt(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	initial := store.Get()
	first, err := store.Save(initial)
	if err != nil {
		t.Fatalf("first Save: %v", err)
	}
	second, err := store.Save(first)
	if err != nil {
		t.Fatalf("second Save: %v", err)
	}
	if !first.UpdatedAt.After(initial.UpdatedAt) || !second.UpdatedAt.After(first.UpdatedAt) {
		t.Fatalf("updated_at did not advance monotonically: initial=%v first=%v second=%v", initial.UpdatedAt, first.UpdatedAt, second.UpdatedAt)
	}
}

func TestCanonicalizeRejectsNonLoopbackHTTPListen(t *testing.T) {
	for _, listen := range []string{
		":18080",
		"0.0.0.0:18080",
		"[::]:18080",
		"192.168.1.10:18080",
	} {
		cfg := DefaultConfig()
		cfg.HTTP.Listen = listen
		if _, err := Canonicalize(cfg); err == nil {
			t.Fatalf("Canonicalize(%q) succeeded, want loopback validation error", listen)
		}
	}
	for _, listen := range []string{
		"127.0.0.1:18080",
		"[::1]:18080",
		"localhost:18080",
	} {
		cfg := DefaultConfig()
		cfg.HTTP.Listen = listen
		if _, err := Canonicalize(cfg); err != nil {
			t.Fatalf("Canonicalize(%q): %v", listen, err)
		}
	}
}
