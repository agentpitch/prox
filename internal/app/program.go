package app

import (
	"context"
	"errors"
	"sync"

	"github.com/openai/pitchprox/internal/httpapi"
)

type Program struct {
	runtime  *Runtime
	wg       sync.WaitGroup
	stopOnce sync.Once
	stopCh   chan struct{}

	httpMu sync.Mutex
	http   *httpapi.Server
}

func NewProgram(configPath string, historyPath string) (*Program, error) {
	rt, err := NewRuntime(configPath, historyPath)
	if err != nil {
		return nil, err
	}
	return &Program{runtime: rt, stopCh: make(chan struct{})}, nil
}

func (p *Program) Runtime() *Runtime { return p.runtime }

func (p *Program) StopRequested() <-chan struct{} { return p.stopCh }

func (p *Program) RequestStop() {
	p.stopOnce.Do(func() { close(p.stopCh) })
}

func (p *Program) Start(ctx context.Context) error {
	if err := p.runtime.Start(ctx); err != nil {
		return err
	}
	if err := p.EnableWebUI(); err != nil {
		_ = p.runtime.Stop()
		return err
	}
	return nil
}

func (p *Program) WebUIRunning() bool {
	p.httpMu.Lock()
	defer p.httpMu.Unlock()
	return p.http != nil && p.http.WebUIEnabled()
}

func (p *Program) EnableWebUI() error {
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
	p.httpMu.Lock()
	srv := p.http
	p.httpMu.Unlock()
	if srv == nil {
		return nil
	}
	srv.SetWebUIEnabled(false)
	return nil
}

func (p *Program) Stop() error {
	p.httpMu.Lock()
	srv := p.http
	p.http = nil
	p.httpMu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
	if p.runtime != nil {
		_ = p.runtime.Stop()
	}
	p.wg.Wait()
	return nil
}
