package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/agentpitch/prox/internal/control"
	"github.com/agentpitch/prox/internal/httpapi"
	"github.com/agentpitch/prox/internal/updater"
)

type Program struct {
	runtime  *Runtime
	wg       sync.WaitGroup
	stopOnce sync.Once
	stopCh   chan struct{}

	// lifecycleMu serializes whole user-visible state transitions. Stop releases
	// it before waiting for HTTP handlers, after publishing stopping=true.
	lifecycleMu sync.Mutex
	stopping    bool
	stopped     bool
	stopDone    chan struct{}

	httpMu   sync.Mutex
	http     *httpapi.Server
	retiring map[*httpapi.Server]struct{}
	update   updater.Service

	stateMu sync.Mutex
	ctx     context.Context
	paused  bool
}

func NewProgram(configPath string, historyPath string) (*Program, error) {
	rt, err := NewRuntime(configPath, historyPath)
	if err != nil {
		return nil, err
	}
	return &Program{runtime: rt, stopCh: make(chan struct{}), stopDone: make(chan struct{})}, nil
}

func (p *Program) Runtime() *Runtime { return p.runtime }

func (p *Program) SetUpdater(service updater.Service) error {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.stopping || p.stopped {
		return fmt.Errorf("program is stopping")
	}
	p.update = service
	p.httpMu.Lock()
	if p.http != nil {
		p.http.SetUpdater(service)
	}
	for server := range p.retiring {
		server.SetUpdater(service)
	}
	p.httpMu.Unlock()
	return nil
}

func (p *Program) StopRequested() <-chan struct{} { return p.stopCh }

func (p *Program) RequestStop() {
	p.stopOnce.Do(func() { close(p.stopCh) })
}

func (p *Program) Start(ctx context.Context) error {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.stopping || p.stopped {
		return fmt.Errorf("program is stopping")
	}
	p.stateMu.Lock()
	p.ctx = ctx
	p.paused = false
	p.stateMu.Unlock()
	if err := p.runtime.Start(ctx); err != nil {
		return err
	}
	if err := p.enableWebUILocked(); err != nil {
		_ = p.runtime.Stop()
		return err
	}
	return nil
}

func (p *Program) WebUIRunning() bool {
	if p.ServicePaused() {
		return false
	}
	p.httpMu.Lock()
	defer p.httpMu.Unlock()
	return p.http != nil && p.http.WebUIEnabled()
}

func (p *Program) EnableWebUI() error {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.stopping || p.stopped {
		return fmt.Errorf("program is stopping")
	}
	return p.enableWebUILocked()
}

func (p *Program) enableWebUILocked() error {
	p.httpMu.Lock()
	defer p.httpMu.Unlock()
	if p.http != nil {
		p.http.SetWebUIEnabled(true)
		return nil
	}
	srv, err := p.newHTTPServer(p.runtime.CurrentConfig().HTTP.Listen)
	if err != nil {
		return err
	}
	p.serveHTTPServerLocked(srv)
	p.runtime.Monitor().AddLog("info", "Web UI listening on %s", p.runtime.WebUIURL())
	return nil
}

func (p *Program) newHTTPServer(addr string) (*httpapi.Server, error) {
	srv, err := httpapi.New(addr, p.runtime, p.RequestStop)
	if err != nil {
		return nil, err
	}
	srv.PauseFunc = p.PauseService
	srv.ResumeFunc = p.ResumeService
	srv.PausedFunc = p.ServicePaused
	srv.ApplyConfigFunc = p.ApplyControlConfig
	srv.WebUIControlFunc = p.controlWebUI
	srv.SetUpdater(p.update)
	if err := srv.Listen(); err != nil {
		_ = srv.Close()
		return nil, err
	}
	return srv, nil
}

// The caller holds lifecycleMu and httpMu, including while adding work to wg.
func (p *Program) serveHTTPServerLocked(srv *httpapi.Server) {
	p.http = srv
	p.wg.Add(1)
	go func(server *httpapi.Server) {
		defer p.wg.Done()
		if err := server.Serve(); err != nil && !errors.Is(err, httpapi.ErrClosed) {
			p.runtime.Monitor().AddLog("error", "http server: %v", err)
		}
		p.httpMu.Lock()
		if p.http == server {
			p.http = nil
		}
		p.httpMu.Unlock()
	}(srv)
}

// ApplyControlConfig serializes the revision check, preview and activation with
// pause/resume/stop and legacy runtime config updates. Rules and proxies are
// swapped for future connections; only an explicitly allowed runtime restart
// may close established relays.
func (p *Program) ApplyControlConfig(req control.ConfigRequest) (control.ConfigResult, error) {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.stopping || p.stopped {
		return control.ConfigResult{}, &control.APIError{Code: "unavailable", Message: "program is stopping"}
	}
	rt := p.runtime
	rt.transitionMu.Lock()
	defer rt.transitionMu.Unlock()
	old := rt.CurrentConfig()
	result := control.ConfigResult{Config: old, PreviousUpdatedAt: old.UpdatedAt}
	fail := func(code, message string) (control.ConfigResult, error) {
		return result, &control.APIError{Code: code, Message: message, CurrentUpdatedAt: old.UpdatedAt}
	}
	rt.runMu.RLock()
	closed, running := rt.closed, rt.running
	rt.runMu.RUnlock()
	if closed {
		return fail("unavailable", "runtime is closed")
	}
	if !req.DryRun && req.ExpectedUpdatedAt.IsZero() {
		return fail("revision_required", "expected_updated_at is required when applying configuration")
	}
	if !req.ExpectedUpdatedAt.IsZero() && !req.ExpectedUpdatedAt.Equal(old.UpdatedAt) {
		return fail("revision_conflict", "configuration changed since it was loaded")
	}
	candidate, plan, err := control.PlanConfig(old, req.Config, running)
	if err != nil {
		return fail("invalid_config", err.Error())
	}
	result.Plan = plan
	if req.DryRun {
		result.Config = candidate
		return result, nil
	}
	if plan.Mode == "no_change" {
		return result, nil
	}
	if plan.RuntimeRestart && !req.AllowDisruptive {
		return fail("disruptive_change", "this change restarts routing and closes intercepted connections; review the plan and set allow_disruptive to apply")
	}
	candidate, eng, interception, err := rt.prepareConfig(candidate)
	if err != nil {
		return fail("invalid_config", err.Error())
	}

	p.httpMu.Lock()
	oldHTTP := p.http
	p.httpMu.Unlock()
	var replacement *httpapi.Server
	if plan.HTTPRebind && oldHTTP != nil {
		// Reserve the socket before activating or saving any change. A busy
		// address must leave the current router, config and control API intact.
		replacement, err = p.newHTTPServer(candidate.HTTP.Listen)
		if err != nil {
			return fail("activation_failed", fmt.Sprintf("bind replacement HTTP listener: %v", err))
		}
		replacement.CopyWebUIStateFrom(oldHTTP)
	}
	if err := rt.applyPreparedConfigTransitionLocked(candidate, eng, interception); err != nil {
		if replacement != nil {
			_ = replacement.Close()
		}
		return fail("activation_failed", err.Error())
	}
	if replacement != nil {
		p.httpMu.Lock()
		p.serveHTTPServerLocked(replacement)
		if p.retiring == nil {
			p.retiring = make(map[*httpapi.Server]struct{})
		}
		p.retiring[oldHTTP] = struct{}{}
		p.wg.Add(1)
		p.httpMu.Unlock()
		go func() {
			defer p.wg.Done()
			// The request applying this change belongs to oldHTTP. Drain from
			// another goroutine so its success response can finish first.
			_ = oldHTTP.Retire(5 * time.Second)
			p.httpMu.Lock()
			delete(p.retiring, oldHTTP)
			p.httpMu.Unlock()
		}()
		rt.Monitor().AddLog("info", "control HTTP listener moved to %s", candidate.HTTP.Listen)
	}
	result.Config = rt.CurrentConfig()
	result.Applied = true
	return result, nil
}

func (p *Program) DisableWebUI() error {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	return p.disableWebUILocked()
}

// Requests accepted by a previous HTTP listener still control the current
// listener. Taking the lifecycle lock prevents a handoff from losing a UI
// enable/disable that overlaps the config transaction.
func (p *Program) controlWebUI(enabled bool) (httpapi.WebUIStatus, error) {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.stopping || p.stopped {
		return httpapi.WebUIStatus{}, fmt.Errorf("program is stopping")
	}
	var err error
	if enabled {
		err = p.resumeServiceLocked()
	} else {
		err = p.disableWebUILocked()
	}
	if err != nil {
		return httpapi.WebUIStatus{}, err
	}
	p.httpMu.Lock()
	srv := p.http
	p.httpMu.Unlock()
	if srv == nil {
		return httpapi.WebUIStatus{Paused: p.ServicePaused()}, nil
	}
	return srv.WebUIStatus(), nil
}

func (p *Program) disableWebUILocked() error {
	p.httpMu.Lock()
	srv := p.http
	p.httpMu.Unlock()
	if srv == nil {
		return nil
	}
	srv.SetWebUIEnabled(false)
	return nil
}

func (p *Program) ServicePaused() bool {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.paused
}

func (p *Program) PauseService() error {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.stopping || p.stopped {
		return nil
	}
	p.stateMu.Lock()
	if p.paused {
		p.stateMu.Unlock()
		return nil
	}
	p.paused = true
	p.stateMu.Unlock()

	if err := p.disableWebUILocked(); err != nil {
		return err
	}
	if err := p.runtime.Pause(); err != nil {
		return err
	}
	p.runtime.Monitor().AddLog("info", "service paused")
	return nil
}

func (p *Program) ResumeService() error {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	return p.resumeServiceLocked()
}

func (p *Program) resumeServiceLocked() error {
	if p.stopping || p.stopped {
		return fmt.Errorf("program is stopping")
	}
	p.stateMu.Lock()
	ctx := p.ctx
	if !p.paused {
		p.stateMu.Unlock()
		return p.enableWebUILocked()
	}
	p.paused = false
	p.stateMu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	if err := p.runtime.Start(ctx); err != nil {
		p.stateMu.Lock()
		p.paused = true
		p.stateMu.Unlock()
		return err
	}
	if err := p.enableWebUILocked(); err != nil {
		_ = p.runtime.Pause()
		p.stateMu.Lock()
		p.paused = true
		p.stateMu.Unlock()
		return fmt.Errorf("enable WebUI after resume: %w", err)
	}
	p.runtime.Monitor().AddLog("info", "service resumed")
	return nil
}

func (p *Program) Stop() error {
	p.lifecycleMu.Lock()
	if p.stopped {
		p.lifecycleMu.Unlock()
		return nil
	}
	if p.stopping {
		done := p.stopDone
		p.lifecycleMu.Unlock()
		<-done
		return nil
	}
	p.stopping = true
	p.stateMu.Lock()
	p.paused = true
	p.stateMu.Unlock()
	p.httpMu.Lock()
	srv := p.http
	p.http = nil
	retiring := make([]*httpapi.Server, 0, len(p.retiring))
	for server := range p.retiring {
		retiring = append(retiring, server)
	}
	p.httpMu.Unlock()
	// Do not hold lifecycleMu while Close waits for HTTP handlers: a handler
	// may already be waiting to enter PauseService or ResumeService. Once
	// stopping is visible, those handlers return without starting new work.
	p.lifecycleMu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
	for _, server := range retiring {
		_ = server.Close()
	}
	if p.update != nil {
		p.update.Close()
	}
	if p.runtime != nil {
		_ = p.runtime.Stop()
	}
	p.wg.Wait()
	p.lifecycleMu.Lock()
	p.stopped = true
	close(p.stopDone)
	p.lifecycleMu.Unlock()
	return nil
}
