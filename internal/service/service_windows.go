//go:build windows

package service

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

type Runner interface {
	Start(ctx context.Context) error
	Stop() error
	StopRequested() <-chan struct{}
}

func RunService(name string, r Runner) error {
	return svc.Run(name, &handler{name: name, runner: r})
}

type handler struct {
	name   string
	runner Runner
}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	_ = args
	elog, _ := eventlog.Open(h.name)
	defer func() {
		if elog != nil {
			_ = elog.Close()
		}
	}()
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.runner.Start(ctx); err != nil {
		if elog != nil {
			_ = elog.Error(1, err.Error())
		}
		return false, 1
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	stopReq := h.runner.StopRequested()
	for {
		select {
		case c, ok := <-req:
			if !ok {
				return false, 0
			}
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				_ = h.runner.Stop()
				return false, 0
			}
		case <-stopReq:
			status <- svc.Status{State: svc.StopPending}
			cancel()
			_ = h.runner.Stop()
			return false, 0
		}
	}
}

func Install(name, displayName, description, exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(name); err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists", name)
	}
	s, err := m.CreateService(name, exePath, mgr.Config{
		DisplayName: displayName,
		Description: description,
		StartType:   mgr.StartAutomatic,
	}, "service")
	if err != nil {
		return err
	}
	defer s.Close()
	return eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
}

func Uninstall(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(name)
	return nil
}

func Start(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func Stop(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	return err
}
