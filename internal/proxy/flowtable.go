package proxy

import (
	"net/netip"
	"sync"
	"time"
)

type Flow struct {
	PID          uint32
	ExePath      string
	ClientIP     netip.Addr
	ClientPort   uint16
	OriginalIP   netip.Addr
	OriginalPort uint16
	IPv6         bool
	Accepted     bool // owned by an accepted transparent connection; deleted on connection close.
	CreatedAt    time.Time
	LastSeen     time.Time
}

type flowKey struct {
	IP   netip.Addr
	Port uint16
}

type FlowTable struct {
	mu      sync.RWMutex
	flows   map[flowKey]Flow
	deletes int
	peak    int
	onEmpty func()
}

const (
	flowMapCompactDeletes = 64
	flowMapCompactRatio   = 4
)

type RedirectDirection uint8

const (
	RedirectNone RedirectDirection = iota
	RedirectAppToListener
	RedirectListenerToApp
)

func NewFlowTable() *FlowTable { return &FlowTable{flows: map[flowKey]Flow{}} }

func (t *FlowTable) Register(f Flow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().UTC()
	if f.CreatedAt.IsZero() {
		f.CreatedAt = now
	}
	f.LastSeen = now
	t.flows[makeFlowKey(f.ClientIP, f.ClientPort)] = f
	if len(t.flows) > t.peak {
		t.peak = len(t.flows)
	}
}

func (t *FlowTable) Lookup(clientIP netip.Addr, clientPort uint16) (Flow, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	f, ok := t.flows[makeFlowKey(clientIP, clientPort)]
	return f, ok
}

func (t *FlowTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.flows)
}

func (t *FlowTable) MarkAccepted(clientIP netip.Addr, clientPort uint16) (Flow, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := makeFlowKey(clientIP, clientPort)
	f, ok := t.flows[k]
	if !ok {
		return Flow{}, false
	}
	f.Accepted = true
	f.LastSeen = time.Now().UTC()
	t.flows[k] = f
	return f, true
}

func (t *FlowTable) RedirectPacket(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, listenerPort uint16) (Flow, RedirectDirection, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if srcPort == listenerPort {
		f, ok := t.flows[makeFlowKey(dstIP, dstPort)]
		if ok {
			return f, RedirectListenerToApp, true
		}
	}
	f, ok := t.flows[makeFlowKey(srcIP, srcPort)]
	if !ok {
		return Flow{}, RedirectNone, false
	}
	if f.OriginalIP == dstIP && f.OriginalPort == dstPort {
		return f, RedirectAppToListener, true
	}
	return Flow{}, RedirectNone, false
}

func (t *FlowTable) Delete(clientIP netip.Addr, clientPort uint16) {
	t.mu.Lock()
	becameEmpty := t.deleteLocked(makeFlowKey(clientIP, clientPort))
	onEmpty := t.onEmpty
	t.mu.Unlock()
	if becameEmpty && onEmpty != nil {
		onEmpty()
	}
}

func (t *FlowTable) Cleanup(maxAge time.Duration) {
	cutoff := time.Now().UTC().Add(-maxAge)
	t.mu.Lock()
	becameEmpty := false
	for k, f := range t.flows {
		if !f.Accepted && f.LastSeen.Before(cutoff) {
			becameEmpty = t.deleteLocked(k) || becameEmpty
		}
	}
	onEmpty := t.onEmpty
	t.mu.Unlock()
	if becameEmpty && onEmpty != nil {
		onEmpty()
	}
}

func (t *FlowTable) SetOnEmpty(fn func()) {
	t.mu.Lock()
	t.onEmpty = fn
	t.mu.Unlock()
}

func (t *FlowTable) deleteLocked(k flowKey) bool {
	if _, ok := t.flows[k]; !ok {
		return false
	}
	wasNonEmpty := len(t.flows) > 0
	delete(t.flows, k)
	t.deletes++
	t.compactMaybeLocked()
	return wasNonEmpty && len(t.flows) == 0
}

func (t *FlowTable) compactMaybeLocked() {
	if len(t.flows) == 0 {
		if t.peak >= flowMapCompactDeletes {
			t.flows = map[flowKey]Flow{}
		}
		t.deletes = 0
		t.peak = 0
		return
	}
	// Rebuilding on a fixed number of closes copies every long-lived flow
	// repeatedly under steady traffic. Compact only after the live set shrinks
	// substantially; ordinary churn can reuse the map's existing capacity.
	if t.deletes < flowMapCompactDeletes || len(t.flows) > t.peak/flowMapCompactRatio {
		return
	}
	next := make(map[flowKey]Flow, len(t.flows))
	for k, flow := range t.flows {
		next[k] = flow
	}
	t.flows = next
	t.deletes = 0
	t.peak = len(next)
}

func makeFlowKey(ip netip.Addr, port uint16) flowKey {
	return flowKey{IP: ip.Unmap(), Port: port}
}
