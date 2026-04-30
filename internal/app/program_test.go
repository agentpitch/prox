package app

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
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
	waitHTTPHealth(t, cfg.HTTP.Listen)
	if status := httpStatus(t, "http://"+cfg.HTTP.Listen+"/"); status != http.StatusServiceUnavailable {
		t.Fatalf("GET / status after disable = %d, want %d", status, http.StatusServiceUnavailable)
	}

	if err := prog.EnableWebUI(); err != nil {
		t.Fatalf("EnableWebUI: %v", err)
	}
	waitHTTPHealth(t, cfg.HTTP.Listen)
	if status := httpStatus(t, "http://"+cfg.HTTP.Listen+"/"); status != http.StatusOK {
		t.Fatalf("GET / status after re-enable = %d, want %d", status, http.StatusOK)
	}
	if !prog.WebUIRunning() {
		t.Fatal("WebUIRunning = false after re-enable")
	}
}

func TestProgramPauseAndResumeThroughHTTPControl(t *testing.T) {
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

	baseURL := "http://" + cfg.HTTP.Listen
	waitHTTPHealth(t, cfg.HTTP.Listen)
	if !prog.Runtime().Running() {
		t.Fatal("runtime not running after start")
	}

	if status := httpPostStatus(t, baseURL+"/api/control/service/pause"); status != http.StatusOK {
		t.Fatalf("POST pause status = %d, want %d", status, http.StatusOK)
	}
	if !prog.ServicePaused() {
		t.Fatal("ServicePaused = false after pause")
	}
	if prog.Runtime().Running() {
		t.Fatal("runtime still running after pause")
	}
	if prog.WebUIRunning() {
		t.Fatal("WebUIRunning = true after pause")
	}
	if status := httpStatus(t, baseURL+"/"); status != http.StatusServiceUnavailable {
		t.Fatalf("GET / status after pause = %d, want %d", status, http.StatusServiceUnavailable)
	}
	if status := httpStatus(t, baseURL+"/api/control/service/status"); status != http.StatusOK {
		t.Fatalf("GET service status after pause = %d, want %d", status, http.StatusOK)
	}

	if status := httpPostStatus(t, baseURL+"/api/control/service/resume"); status != http.StatusOK {
		t.Fatalf("POST resume status = %d, want %d", status, http.StatusOK)
	}
	if prog.ServicePaused() {
		t.Fatal("ServicePaused = true after resume")
	}
	if !prog.Runtime().Running() {
		t.Fatal("runtime not running after resume")
	}
	waitHTTPHealth(t, cfg.HTTP.Listen)
	if status := httpStatus(t, baseURL+"/"); status != http.StatusOK {
		t.Fatalf("GET / status after resume = %d, want %d", status, http.StatusOK)
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

func httpStatus(t *testing.T, url string) int {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func httpPostStatus(t *testing.T, url string) int {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
