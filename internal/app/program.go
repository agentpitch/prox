package app

import (
	"context"
	"errors"
	"sync"

	"github.com/openai/pitchprox/internal/httpapi"
)

type Program struct {
	runtime  *Runtime
	http     *httpapi.Server
	wg       sync.WaitGroup
	stopOnce sync.Once
	stopCh   chan struct{}
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
	srv, err := httpapi.New(p.runtime.CurrentConfig().HTTP.Listen, p.runtime, p.RequestStop)
	if err != nil {
		_ = p.runtime.Stop()
		return err
	}
	p.http = srv
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := srv.Start(); err != nil && !errors.Is(err, httpapi.ErrClosed) {
			p.runtime.Monitor().AddLog("error", "http server: %v", err)
		}
	}()
	p.runtime.Monitor().AddLog("info", "Web UI listening on %s", p.runtime.WebUIURL())
	return nil
}

func (p *Program) Stop() error {
	if p.http != nil {
		_ = p.http.Close()
	}
	if p.runtime != nil {
		_ = p.runtime.Stop()
	}
	p.wg.Wait()
	return nil
}
