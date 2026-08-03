package app

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
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
	cleanupBeforeTempDir(t, tmp, prog.Stop)

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
	cleanupBeforeTempDir(t, tmp, prog.Stop)

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

func TestProgramSerializesPauseThenResume(t *testing.T) {
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
	cleanupBeforeTempDir(t, tmp, prog.Stop)

	prog.runtime.transitionMu.Lock()
	transitionLocked := true
	defer func() {
		if transitionLocked {
			prog.runtime.transitionMu.Unlock()
		}
	}()
	pauseDone := make(chan error, 1)
	go func() { pauseDone <- prog.PauseService() }()
	deadline := time.Now().Add(2 * time.Second)
	for !prog.ServicePaused() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !prog.ServicePaused() {
		t.Fatal("PauseService did not enter the lifecycle transition")
	}

	resumeCalled := make(chan struct{})
	resumeDone := make(chan error, 1)
	go func() {
		close(resumeCalled)
		resumeDone <- prog.ResumeService()
	}()
	<-resumeCalled
	select {
	case err := <-resumeDone:
		t.Fatalf("ResumeService bypassed the in-flight pause: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if !prog.ServicePaused() {
		t.Fatal("ResumeService changed paused state before PauseService completed")
	}

	prog.runtime.transitionMu.Unlock()
	transitionLocked = false
	select {
	case err := <-pauseDone:
		if err != nil {
			t.Fatalf("PauseService: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PauseService did not finish after the runtime transition was released")
	}
	select {
	case err := <-resumeDone:
		if err != nil {
			t.Fatalf("ResumeService: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ResumeService did not follow the completed pause")
	}
	if prog.ServicePaused() || !prog.Runtime().Running() || !prog.WebUIRunning() {
		t.Fatal("pause followed by resume did not leave the program fully running")
	}
}

func TestProgramStopDoesNotDeadlockWithControlHandler(t *testing.T) {
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
	cleanupBeforeTempDir(t, tmp, prog.Stop)
	waitHTTPHealth(t, cfg.HTTP.Listen)

	prog.httpMu.Lock()
	srv := prog.http
	prog.httpMu.Unlock()
	if srv == nil {
		t.Fatal("HTTP server is not running")
	}
	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseHandler) }) })
	srv.PauseFunc = func() error {
		close(handlerEntered)
		<-releaseHandler
		return prog.PauseService()
	}

	requestDone := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Post("http://"+cfg.HTTP.Listen+"/api/control/service/pause", "application/json", strings.NewReader(`{}`))
		if resp != nil {
			_ = resp.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("control handler did not enter PauseFunc")
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- prog.Stop() }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		prog.lifecycleMu.Lock()
		stopping := prog.stopping
		prog.lifecycleMu.Unlock()
		if stopping {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Stop did not publish stopping state")
		}
		time.Sleep(5 * time.Millisecond)
	}
	secondStopDone := make(chan error, 1)
	go func() { secondStopDone <- prog.Stop() }()
	select {
	case err := <-secondStopDone:
		t.Fatalf("concurrent Stop returned before the active shutdown completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseHandler) })
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop deadlocked waiting for a control handler")
	}
	select {
	case err := <-secondStopDone:
		if err != nil {
			t.Fatalf("concurrent Stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Stop did not observe shutdown completion")
	}
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("control request did not return after Stop")
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
