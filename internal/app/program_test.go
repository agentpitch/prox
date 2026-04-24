package app

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestProgramCanDisableAndReenableWebUI(t *testing.T) {
	tmp := t.TempDir()
	prog, err := NewProgram(filepath.Join(tmp, "config.json"), filepath.Join(tmp, "history"))
	if err != nil {
		t.Fatalf("NewProgram: %v", err)
	}

	cfg := runtimeTestConfig()
	cfg.HTTP.Listen = freeTCPAddr(t)
	if err := prog.Runtime().UpdateConfig(cfg); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := prog.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = prog.Stop() }()

	waitHTTPHealth(t, cfg.HTTP.Listen)
	if !prog.WebUIRunning() {
		t.Fatal("WebUIRunning = false after start")
	}

	if err := prog.DisableWebUI(); err != nil {
		t.Fatalf("DisableWebUI: %v", err)
	}
	if prog.WebUIRunning() {
		t.Fatal("WebUIRunning = true after disable")
	}
	if canDial(cfg.HTTP.Listen) {
		t.Fatal("web UI socket still accepts connections after disable")
	}

	if err := prog.EnableWebUI(); err != nil {
		t.Fatalf("EnableWebUI: %v", err)
	}
	waitHTTPHealth(t, cfg.HTTP.Listen)
	if !prog.WebUIRunning() {
		t.Fatal("WebUIRunning = false after re-enable")
	}
}

func freeTCPAddr(t *testing.T) string {
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

func waitHTTPHealth(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{Timeout: 150 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	url := "http://" + addr + "/api/health"
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", url)
}

func canDial(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
