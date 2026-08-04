package app

import (
	"context"
	"net/netip"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/monitor"
	"github.com/agentpitch/prox/internal/proxy"
	"github.com/agentpitch/prox/internal/win"
)

type directObserverMonitor interface {
	UIActive() bool
	UIWake() <-chan struct{}
	UpsertConnection(monitor.Connection)
	AddRuleConnection(string, string, config.RuleAction)
	AddRuleConditionConnection(string, string, config.RuleAction, monitor.RuleConditionMatch)
	AddLog(string, string, ...interface{})
}

type directObserver struct {
	Monitor         directObserverMonitor
	Flows           *proxy.FlowTable
	ActiveInterval  time.Duration
	DormantInterval time.Duration
	Decide          func(win.TCPConnection) (monitor.Connection, monitor.RuleConditionMatch, bool)
	List            func() ([]win.TCPConnection, error)
	ReleaseDormant  func()
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
	dormantReleased := false
	releaseDormant := func() {
		if dormantReleased {
			return
		}
		if o.ReleaseDormant != nil {
			o.ReleaseDormant()
		}
		dormantReleased = true
	}
	defer releaseDormant()
	timer := time.NewTimer(time.Hour)
	stopAndDrainTimer(timer)
	defer timer.Stop()
	for {
		if o.Monitor.UIActive() {
			dormantReleased = false
			seen = o.scan(list, seen)
			if !waitObserverTimer(ctx, timer, nil, activeInterval) {
				o.finalizeAll(seen)
				return
			}
			continue
		}
		if len(seen) > 0 {
			o.finalizeAll(seen)
			seen = map[string]monitor.Connection{}
		}
		releaseDormant()
		wake := o.Monitor.UIWake()
		if wake == nil {
			if !waitObserverTimer(ctx, timer, nil, dormantInterval) {
				return
			}
			continue
		}
		// The production monitor uses a buffered wake channel and signals every
		// transition that can make the observer useful. Waiting on that signal
		// avoids waking an otherwise idle service every few seconds. Keep the
		// timer above only as a compatibility fallback for monitors without a
		// wake channel.
		if !waitObserverWake(ctx, wake) {
			return
		}
	}
}

func waitObserverWake(ctx context.Context, wake <-chan struct{}) bool {
	select {
	case <-ctx.Done():
		return false
	case <-wake:
		return true
	}
}

func waitObserverTimer(ctx context.Context, timer *time.Timer, wake <-chan struct{}, d time.Duration) bool {
	timer.Reset(d)
	defer stopAndDrainTimer(timer)
	if wake == nil {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	select {
	case <-ctx.Done():
		return false
	case <-wake:
		return true
	case <-timer.C:
		return true
	}
}

func stopAndDrainTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (o *directObserver) scan(list func() ([]win.TCPConnection, error), seen map[string]monitor.Connection) map[string]monitor.Connection {
	items, err := list()
	if err != nil {
		o.Monitor.AddLog("warn", "tcp observer: %v", err)
		return seen
	}
	next := make(map[string]monitor.Connection, len(items))
	for _, item := range items {
		if !item.LocalIP.IsValid() || !item.RemoteIP.IsValid() {
			continue
		}
		if o.isIntercepted(item.LocalIP, item.LocalPort) {
			continue
		}
		c, ruleMatch, ok := o.Decide(item)
		if !ok {
			continue
		}
		if prev, ok := seen[c.ID]; ok {
			c.CreatedAt = prev.CreatedAt
			c.BytesUp = prev.BytesUp
			c.BytesDown = prev.BytesDown
		} else {
			o.Monitor.AddRuleConditionConnection(c.RuleID, c.RuleName, c.Action, ruleMatch)
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
	return next
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
