//go:build windows

package windivert

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/openai/pitchprox/internal/config"
	"github.com/openai/pitchprox/internal/monitor"
	"github.com/openai/pitchprox/internal/proxy"
	"github.com/openai/pitchprox/internal/util"
	"github.com/openai/pitchprox/internal/win"
)

type PlanDecision struct {
	Definitive    bool
	NeedsHostname bool
	RuleID        string
	RuleName      string
	Action        config.RuleAction
	ProxyID       string
	ChainID       string
}

type PlanFunc func(flow proxy.Flow) PlanDecision

type Engine struct {
	ListenerPort int
	Flows        *proxy.FlowTable
	Monitor      *monitor.Bus
	Plan         PlanFunc

	classifier   Handle
	redirector   Handle
	redirectorMu sync.Mutex
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	localIPs     map[netip.Addr]struct{}
	servicePID   uint32
	owners       *win.OwnerCache
}

const (
	classifierFilter         = "outbound and tcp and !loopback and !impostor and tcp.Syn and !tcp.Ack and !tcp.Rst"
	classifierPriority       = 200
	redirectorPriority       = 100
	pendingFlowCleanupMaxAge = 30 * time.Second
	cleanupInterval          = 10 * time.Second
	ownerRefreshMaxAge       = 2 * time.Second
)

func (e *Engine) Start(ctx context.Context) error {
	if e.Flows == nil {
		e.Flows = proxy.NewFlowTable()
	}
	ips, err := util.LocalIPs()
	if err != nil {
		return err
	}
	e.localIPs = ips
	e.servicePID = uint32(os.Getpid())
	h, err := Open(classifierFilter, LayerNetwork, classifierPriority, 0)
	if err != nil {
		return err
	}
	e.classifier = h
	e.owners = win.NewOwnerCache(2 * time.Second)
	_ = e.owners.ForceRefresh()
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.wg.Add(2)
	go e.classifierLoop(ctx, h)
	go e.cleanup(ctx)
	if e.Monitor != nil {
		e.Monitor.AddLog("info", "WinDivert started with selective SYN classifier and lazy shared redirector")
	}
	return nil
}

func (e *Engine) Close() error {
	if e.cancel != nil {
		e.cancel()
	}
	if e.classifier != 0 {
		_ = e.classifier.Close()
		e.classifier = 0
	}
	e.closeRedirector()
	e.wg.Wait()
	return nil
}

func (e *Engine) classifierLoop(ctx context.Context, h Handle) {
	defer e.wg.Done()
	buf := make([]byte, 0xFFFF)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		addr := &Address{}
		n, err := h.Recv(buf, addr)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if e.Monitor != nil {
				e.Monitor.AddLog("error", "WinDivert classifier recv: %v", err)
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		raw := buf[:n]
		pkt, err := ParsePacket(raw)
		if err != nil {
			_, _ = h.Send(raw, addr)
			continue
		}
		if e.isLocal(pkt.Dst) {
			_, _ = h.Send(pkt.Raw, addr)
			continue
		}
		pid, exe, tries, ok := e.lookup(pkt)
		if !ok {
			if e.Monitor != nil {
				e.Monitor.AddLog("warn", "owner lookup failed for %s:%d -> %s:%d, passing direct", pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort)
			}
			_, _ = h.Send(pkt.Raw, addr)
			continue
		}
		if pid == e.servicePID {
			_, _ = h.Send(pkt.Raw, addr)
			continue
		}
		flow := proxy.Flow{PID: pid, ExePath: exe, ClientIP: pkt.Src, ClientPort: pkt.SrcPort, OriginalIP: pkt.Dst, OriginalPort: pkt.DstPort, IPv6: pkt.IPv6}
		plan := e.evaluatePlan(flow)
		if plan.Definitive && plan.Action == config.ActionDirect {
			_, _ = h.Send(pkt.Raw, addr)
			continue
		}
		e.Flows.Register(flow)
		if err := e.ensureRedirector(ctx); err != nil {
			e.Flows.Delete(flow.ClientIP, flow.ClientPort)
			if e.Monitor != nil {
				e.Monitor.AddLog("error", "shared redirector start failed for %s:%d -> %s:%d: %v", pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort, err)
			}
			_, _ = h.Send(pkt.Raw, addr)
			continue
		}
		if e.Monitor != nil {
			e.Monitor.AddLog("debug", "intercepted pid=%d exe=%s %s:%d -> %s:%d after %d owner tries action=%s rule=%s", pid, exe, pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort, tries, plan.Action, plan.RuleName)
		}
		pkt.SetDst(flow.ClientIP, uint16(e.ListenerPort))
		_ = CalcChecksums(pkt.Raw, addr)
		_, _ = h.Send(pkt.Raw, addr)
	}
}

func (e *Engine) redirectorLoop(ctx context.Context, h Handle) {
	defer e.wg.Done()
	buf := make([]byte, 0xFFFF)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		addr := &Address{}
		n, err := h.Recv(buf, addr)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if !e.isCurrentRedirector(h) {
				return
			}
			if e.Monitor != nil {
				e.Monitor.AddLog("warn", "WinDivert redirector recv: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		raw := buf[:n]
		pkt, err := ParsePacket(raw)
		if err != nil {
			_, _ = h.Send(raw, addr)
			continue
		}
		if e.rewriteRedirectPacket(&pkt) {
			_ = CalcChecksums(pkt.Raw, addr)
		}
		_, _ = h.Send(pkt.Raw, addr)
	}
}

func (e *Engine) cleanup(ctx context.Context) {
	defer e.wg.Done()
	t := time.NewTicker(cleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Flows.Cleanup(pendingFlowCleanupMaxAge)
			if e.Flows.Len() == 0 {
				e.closeIdleRedirector()
			}
		}
	}
}

func (e *Engine) isLocal(ip netip.Addr) bool {
	if ip.IsLoopback() {
		return true
	}
	_, ok := e.localIPs[ip.Unmap()]
	return ok
}

func (e *Engine) lookup(pkt Packet) (uint32, string, int, bool) {
	tries := 1
	_ = e.owners.RefreshIfStale(ownerRefreshMaxAge)
	if pid, exe, ok := e.owners.Lookup(pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort); ok {
		return pid, exe, tries, true
	}
	_ = e.owners.ForceRefresh()
	deadline := time.Now().Add(120 * time.Millisecond)
	for time.Now().Before(deadline) {
		tries++
		if pid, exe, ok := e.owners.Lookup(pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort); ok {
			return pid, exe, tries, true
		}
		time.Sleep(6 * time.Millisecond)
	}
	return 0, "", tries, false
}

func (e *Engine) evaluatePlan(flow proxy.Flow) PlanDecision {
	if e.Plan == nil {
		return PlanDecision{Definitive: true, Action: config.ActionDirect}
	}
	return e.Plan(flow)
}

func (e *Engine) ensureRedirector(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	e.redirectorMu.Lock()
	defer e.redirectorMu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if e.redirector != 0 {
		return nil
	}
	h, err := Open(buildRedirectorFilter(e.ListenerPort), LayerNetwork, redirectorPriority, 0)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		_ = h.Close()
		return ctx.Err()
	default:
	}
	e.redirector = h
	e.wg.Add(1)
	go e.redirectorLoop(ctx, h)
	return nil
}

func (e *Engine) closeRedirector() {
	e.redirectorMu.Lock()
	h := e.redirector
	e.redirector = 0
	e.redirectorMu.Unlock()
	if h != 0 {
		_ = h.Close()
	}
}

func (e *Engine) closeIdleRedirector() {
	e.redirectorMu.Lock()
	if e.Flows.Len() != 0 {
		e.redirectorMu.Unlock()
		return
	}
	h := e.redirector
	e.redirector = 0
	e.redirectorMu.Unlock()
	if h != 0 {
		_ = h.Close()
	}
}

func (e *Engine) isCurrentRedirector(h Handle) bool {
	e.redirectorMu.Lock()
	defer e.redirectorMu.Unlock()
	return e.redirector == h
}

func (e *Engine) rewriteRedirectPacket(pkt *Packet) bool {
	listenerPort := uint16(e.ListenerPort)
	flow, direction, ok := e.Flows.RedirectPacket(pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort, listenerPort)
	if !ok {
		return false
	}
	switch direction {
	case proxy.RedirectListenerToApp:
		pkt.SetSrc(flow.OriginalIP, flow.OriginalPort)
		return true
	case proxy.RedirectAppToListener:
		pkt.SetDst(flow.ClientIP, listenerPort)
		return true
	default:
		return false
	}
}

func buildRedirectorFilter(listenerPort int) string {
	return fmt.Sprintf("outbound and tcp and !impostor and (!loopback or tcp.SrcPort == %d or tcp.DstPort == %d)", listenerPort, listenerPort)
}
