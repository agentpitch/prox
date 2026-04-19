package app

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/pitchprox/internal/config"
	"github.com/openai/pitchprox/internal/monitor"
	"github.com/openai/pitchprox/internal/win"
)

type fakeDirectObserverMonitor struct {
	mu      sync.RWMutex
	active  bool
	wake    chan struct{}
	upserts chan monitor.Connection
}

func newFakeDirectObserverMonitor(active bool) *fakeDirectObserverMonitor {
	return &fakeDirectObserverMonitor{
		active:  active,
		wake:    make(chan struct{}, 4),
		upserts: make(chan monitor.Connection, 16),
	}
}

func (m *fakeDirectObserverMonitor) UIActive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
}

func (m *fakeDirectObserverMonitor) UIWake() <-chan struct{} { return m.wake }

func (m *fakeDirectObserverMonitor) UpsertConnection(c monitor.Connection) {
	m.upserts <- c
}

func (m *fakeDirectObserverMonitor) AddRuleConnection(string, string, config.RuleAction) {}

func (m *fakeDirectObserverMonitor) AddLog(string, string, ...interface{}) {}

func (m *fakeDirectObserverMonitor) setActive(active bool) {
	m.mu.Lock()
	m.active = active
	m.mu.Unlock()
	if active {
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
}

func waitForObserverState(t *testing.T, ch <-chan monitor.Connection, want string, timeout time.Duration) monitor.Connection {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case item := <-ch:
			if item.State == want {
				return item
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for observer state %q", want)
		}
	}
}

func TestDirectObserverDormantFinalizesSeenConnections(t *testing.T) {
	mon := newFakeDirectObserverMonitor(true)
	var listCalls atomic.Int32
	observer := &directObserver{
		Monitor:         mon,
		ActiveInterval:  50 * time.Millisecond,
		DormantInterval: 10 * time.Millisecond,
		List: func() ([]win.TCPConnection, error) {
			listCalls.Add(1)
			return []win.TCPConnection{{
				PID:        42,
				ExePath:    `C:\demo.exe`,
				LocalIP:    netip.MustParseAddr("127.0.0.1"),
				LocalPort:  50000,
				RemoteIP:   netip.MustParseAddr("1.1.1.1"),
				RemotePort: 443,
				SeenAt:     time.Now().UTC(),
			}}, nil
		},
		Decide: func(item win.TCPConnection) (monitor.Connection, bool) {
			return monitor.Connection{
				ID:           monitor.ConnID(item.PID, item.LocalIP, item.LocalPort, item.RemoteIP, item.RemotePort),
				PID:          item.PID,
				ExePath:      item.ExePath,
				SourceIP:     item.LocalIP.String(),
				SourcePort:   item.LocalPort,
				OriginalIP:   item.RemoteIP.String(),
				OriginalPort: item.RemotePort,
				Action:       config.ActionDirect,
				State:        "open",
				CreatedAt:    item.SeenAt,
				Count:        1,
			}, true
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		observer.Start(ctx)
	}()

	open := waitForObserverState(t, mon.upserts, "open", time.Second)
	mon.setActive(false)
	closed := waitForObserverState(t, mon.upserts, "closed", time.Second)

	if open.ID != closed.ID {
		t.Fatalf("closed connection id = %q, want %q", closed.ID, open.ID)
	}

	time.Sleep(90 * time.Millisecond)
	if got := listCalls.Load(); got != 1 {
		t.Fatalf("list calls = %d, want 1 after observer became dormant", got)
	}

	cancel()
	<-done
}

func TestDirectObserverWakesImmediatelyOnUIActivity(t *testing.T) {
	mon := newFakeDirectObserverMonitor(false)
	var listCalls atomic.Int32
	observer := &directObserver{
		Monitor:         mon,
		ActiveInterval:  50 * time.Millisecond,
		DormantInterval: 500 * time.Millisecond,
		List: func() ([]win.TCPConnection, error) {
			listCalls.Add(1)
			return []win.TCPConnection{{
				PID:        7,
				ExePath:    `C:\wake.exe`,
				LocalIP:    netip.MustParseAddr("127.0.0.1"),
				LocalPort:  40000,
				RemoteIP:   netip.MustParseAddr("8.8.8.8"),
				RemotePort: 53,
				SeenAt:     time.Now().UTC(),
			}}, nil
		},
		Decide: func(item win.TCPConnection) (monitor.Connection, bool) {
			return monitor.Connection{
				ID:           monitor.ConnID(item.PID, item.LocalIP, item.LocalPort, item.RemoteIP, item.RemotePort),
				PID:          item.PID,
				ExePath:      item.ExePath,
				SourceIP:     item.LocalIP.String(),
				SourcePort:   item.LocalPort,
				OriginalIP:   item.RemoteIP.String(),
				OriginalPort: item.RemotePort,
				Action:       config.ActionDirect,
				State:        "open",
				CreatedAt:    item.SeenAt,
				Count:        1,
			}, true
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		observer.Start(ctx)
	}()

	time.Sleep(40 * time.Millisecond)
	if got := listCalls.Load(); got != 0 {
		t.Fatalf("list calls before wake = %d, want 0", got)
	}

	start := time.Now()
	mon.setActive(true)
	_ = waitForObserverState(t, mon.upserts, "open", time.Second)
	if elapsed := time.Since(start); elapsed >= 400*time.Millisecond {
		t.Fatalf("observer wake took %v, expected faster than dormant interval", elapsed)
	}

	cancel()
	<-done
}
