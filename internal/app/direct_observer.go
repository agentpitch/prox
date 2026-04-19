package app

import (
	"context"
	"net/netip"
	"time"

	"github.com/openai/pitchprox/internal/config"
	"github.com/openai/pitchprox/internal/monitor"
	"github.com/openai/pitchprox/internal/proxy"
	"github.com/openai/pitchprox/internal/win"
)

type directObserverMonitor interface {
	UIActive() bool
	UIWake() <-chan struct{}
	UpsertConnection(monitor.Connection)
	AddRuleConnection(string, string, config.RuleAction)
	AddLog(string, string, ...interface{})
}

type directObserver struct {
	Monitor         directObserverMonitor
	Flows           *proxy.FlowTable
	ActiveInterval  time.Duration
	DormantInterval time.Duration
	Decide          func(win.TCPConnection) (monitor.Connection, bool)
	List            func() ([]win.TCPConnection, error)
}

func (o *directObserver) Start(ctx context.Context) {
	if o == nil || o.Monitor == nil || o.Decide == nil {
		return
	}
	activeInterval := o.ActiveInterval
	if activeInterval <= 0 {
		activeInterval = 5 * time.Second
	}
	dormantInterval := o.DormantInterval
	if dormantInterval <= 0 {
		dormantInterval = 5 * time.Second
	}
	list := o.List
	if list == nil {
		list = win.ListTCPConnections
	}
	seen := map[string]monitor.Connection{}
	for {
		if o.Monitor.UIActive() {
			o.scan(list, seen)
			select {
			case <-ctx.Done():
				o.finalizeAll(seen)
				return
			case <-time.After(activeInterval):
			}
			continue
		}
		if len(seen) > 0 {
			o.finalizeAll(seen)
			clear(seen)
		}
		wake := o.Monitor.UIWake()
		if wake == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(dormantInterval):
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(dormantInterval):
		}
	}
}

func (o *directObserver) scan(list func() ([]win.TCPConnection, error), seen map[string]monitor.Connection) {
	items, err := list()
	if err != nil {
		o.Monitor.AddLog("warn", "tcp observer: %v", err)
		return
	}
	next := make(map[string]monitor.Connection, len(items))
	for _, item := range items {
		if !item.LocalIP.IsValid() || !item.RemoteIP.IsValid() {
			continue
		}
		if o.isIntercepted(item.LocalIP, item.LocalPort) {
			continue
		}
		c, ok := o.Decide(item)
		if !ok {
			continue
		}
		if prev, ok := seen[c.ID]; ok {
			c.CreatedAt = prev.CreatedAt
			c.BytesUp = prev.BytesUp
			c.BytesDown = prev.BytesDown
		} else {
			o.Monitor.AddRuleConnection(c.RuleID, c.RuleName, c.Action)
		}
		c.State = "open"
		o.Monitor.UpsertConnection(c)
		next[c.ID] = c
	}
	for id, prev := range seen {
		if _, ok := next[id]; ok {
			continue
		}
		closed := prev
		closed.State = "closed"
		o.Monitor.UpsertConnection(closed)
	}
	for k := range seen {
		delete(seen, k)
	}
	for id, item := range next {
		seen[id] = item
	}
}

func (o *directObserver) finalizeAll(seen map[string]monitor.Connection) {
	for _, prev := range seen {
		closed := prev
		closed.State = "closed"
		o.Monitor.UpsertConnection(closed)
	}
}

func (o *directObserver) isIntercepted(ip netip.Addr, port uint16) bool {
	if o.Flows == nil {
		return false
	}
	_, ok := o.Flows.Lookup(ip, port)
	return ok
}
