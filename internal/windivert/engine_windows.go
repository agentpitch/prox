//go:build windows

package windivert

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/monitor"
	"github.com/agentpitch/prox/internal/proxy"
	"github.com/agentpitch/prox/internal/util"
	"github.com/agentpitch/prox/internal/win"
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

	classifier             Handle
	redirector             Handle
	redirectorMu           sync.Mutex
	cancel                 context.CancelFunc
	wg                     sync.WaitGroup
	localIPs               map[netip.Addr]struct{}
	servicePID             uint32
	owners                 *win.OwnerCache
	flowWake               chan struct{}
	flowEmpty              chan struct{}
	packetErrMu            sync.Mutex
	lastPacketErr          time.Time
	suppressedPacketErrors uint64
}

const (
	classifierFilter         = "outbound and tcp and !loopback and !impostor and tcp.Syn and !tcp.Ack and !tcp.Rst"
	classifierPriority       = 200
	redirectorPriority       = 100
	pendingFlowCleanupMaxAge = 30 * time.Second
	cleanupInterval          = 30 * time.Second
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
	e.flowWake = make(chan struct{}, 1)
	e.flowEmpty = make(chan struct{}, 1)
	e.Flows.SetOnEmpty(func() {
		select {
		case e.flowEmpty <- struct{}{}:
		default:
		}
	})
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
	e.Flows.SetOnEmpty(nil)
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
			e.sendPacket(h, raw, addr, "classifier parse fallback")
			continue
		}
		if e.isLocal(pkt.Dst) {
			e.sendPacket(h, pkt.Raw, addr, "classifier local passthrough")
			continue
		}
		pid, exe, tries, ok := e.lookup(pkt)
		if !ok {
			if e.Monitor != nil {
				e.Monitor.AddLog("warn", "owner lookup failed for %s:%d -> %s:%d, passing direct", pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort)
			}
			e.sendPacket(h, pkt.Raw, addr, "classifier unknown-owner passthrough")
			continue
		}
		if pid == e.servicePID {
			e.sendPacket(h, pkt.Raw, addr, "classifier self passthrough")
			continue
		}
		flow := proxy.Flow{PID: pid, ExePath: exe, ClientIP: pkt.Src, ClientPort: pkt.SrcPort, OriginalIP: pkt.Dst, OriginalPort: pkt.DstPort, IPv6: pkt.IPv6}
		plan := e.evaluatePlan(flow)
		if plan.Definitive && plan.Action == config.ActionDirect {
			e.sendPacket(h, pkt.Raw, addr, "classifier direct passthrough")
			continue
		}
		e.Flows.Register(flow)
		e.signalFlowWake()
		if err := e.ensureRedirector(ctx); err != nil {
			e.Flows.Delete(flow.ClientIP, flow.ClientPort)
			if e.Monitor != nil {
				e.Monitor.AddLog("error", "shared redirector start failed for %s:%d -> %s:%d: %v", pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort, err)
			}
			e.sendPacket(h, pkt.Raw, addr, "classifier redirector fallback")
			continue
		}
		if e.Monitor != nil {
			e.Monitor.AddLog("debug", "intercepted pid=%d exe=%s %s:%d -> %s:%d after %d owner tries action=%s rule=%s", pid, exe, pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort, tries, plan.Action, plan.RuleName)
		}
		original := append([]byte(nil), pkt.Raw...)
		pkt.SetDst(flow.ClientIP, uint16(e.ListenerPort))
		if err := CalcChecksums(pkt.Raw, addr); err != nil {
			e.Flows.Delete(flow.ClientIP, flow.ClientPort)
			e.logPacketError("classifier checksum", err)
			e.sendPacket(h, original, addr, "classifier checksum fallback")
			continue
		}
		if !e.sendPacket(h, pkt.Raw, addr, "classifier redirect") {
			e.Flows.Delete(flow.ClientIP, flow.ClientPort)
			e.sendPacket(h, original, addr, "classifier redirect fallback")
		}
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
			e.sendPacket(h, raw, addr, "redirector parse fallback")
			continue
		}
		if e.rewriteRedirectPacket(&pkt) {
			if err := CalcChecksums(pkt.Raw, addr); err != nil {
				e.logPacketError("redirector checksum", err)
				continue
			}
		}
		e.sendPacket(h, pkt.Raw, addr, "redirector send")
	}
}

func (e *Engine) cleanup(ctx context.Context) {
	defer e.wg.Done()
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var timerC <-chan time.Time
	arm := func() {
		if timerC == nil {
			timer.Reset(cleanupInterval)
			timerC = timer.C
		}
	}
	stop := func() {
		if timerC == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.flowWake:
			arm()
		case <-e.flowEmpty:
			if e.Flows.Len() == 0 {
				stop()
				e.closeIdleRedirector()
			}
		case <-timerC:
			timerC = nil
			e.Flows.Cleanup(pendingFlowCleanupMaxAge)
			if e.Flows.Len() == 0 {
				e.closeIdleRedirector()
			} else {
				arm()
			}
		}
	}
}

func (e *Engine) signalFlowWake() {
	select {
	case e.flowWake <- struct{}{}:
	default:
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

func (e *Engine) sendPacket(h Handle, packet []byte, addr *Address, operation string) bool {
	n, err := h.Send(packet, addr)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	if err == nil {
		return true
	}
	e.logPacketError(operation, err)
	return false
}

func (e *Engine) logPacketError(operation string, err error) {
	if e == nil || err == nil || e.Monitor == nil {
		return
	}
	now := time.Now()
	e.packetErrMu.Lock()
	if now.Sub(e.lastPacketErr) < 5*time.Second {
		e.suppressedPacketErrors++
		e.packetErrMu.Unlock()
		return
	}
	suppressed := e.suppressedPacketErrors
	e.suppressedPacketErrors = 0
	e.lastPacketErr = now
	e.packetErrMu.Unlock()
	if suppressed > 0 {
		e.Monitor.AddLog("error", "WinDivert %s failed: %v (%d similar errors suppressed)", operation, err, suppressed)
		return
	}
	e.Monitor.AddLog("error", "WinDivert %s failed: %v", operation, err)
}
