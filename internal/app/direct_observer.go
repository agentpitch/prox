package app

import (
	"context"
	"net/netip"
	"time"

	"github.com/openai/pitchprox/internal/monitor"
	"github.com/openai/pitchprox/internal/proxy"
	"github.com/openai/pitchprox/internal/win"
)

type directObserver struct {
	Monitor        *monitor.Bus
	Flows          *proxy.FlowTable
	ActiveInterval time.Duration
	IdleInterval   time.Duration
	Decide         func(win.TCPConnection) (monitor.Connection, bool)
}

func (o *directObserver) Start(ctx context.Context) {
	if o == nil || o.Monitor == nil || o.Decide == nil {
		return
	}
	activeInterval := o.ActiveInterval
	if activeInterval <= 0 {
		activeInterval = 5 * time.Second
	}
	idleInterval := o.IdleInterval
	if idleInterval <= 0 {
		idleInterval = 20 * time.Second
	}
	seen := map[string]monitor.Connection{}
	for {
		interval := idleInterval
		if o.Monitor.UIActive() {
			interval = activeInterval
		}
		o.scan(seen)
		select {
		case <-ctx.Done():
			o.finalizeAll(seen)
			return
		case <-time.After(interval):
		}
	}
}

func (o *directObserver) scan(seen map[string]monitor.Connection) {
	items, err := win.ListTCPConnections()
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
