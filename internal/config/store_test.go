package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
