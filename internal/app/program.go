package app

import (
	"context"
	"errors"
	"fmt"
	"sync"

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

	httpMu sync.Mutex
	http   *httpapi.Server
	update updater.Service

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
	srv, err := httpapi.New(p.runtime.CurrentConfig().HTTP.Listen, p.runtime, p.RequestStop)
	if err != nil {
		return err
	}
	srv.PauseFunc = p.PauseService
	srv.ResumeFunc = p.ResumeService
	srv.PausedFunc = p.ServicePaused
	srv.SetUpdater(p.update)
	if err := srv.Listen(); err != nil {
		_ = srv.Close()
		return err
	}
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
	p.runtime.Monitor().AddLog("info", "Web UI listening on %s", p.runtime.WebUIURL())
	return nil
}

func (p *Program) DisableWebUI() error {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	return p.disableWebUILocked()
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
	p.httpMu.Unlock()
	// Do not hold lifecycleMu while Close waits for HTTP handlers: a handler
	// may already be waiting to enter PauseService or ResumeService. Once
	// stopping is visible, those handlers return without starting new work.
	p.lifecycleMu.Unlock()
	if srv != nil {
		_ = srv.Close()
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
