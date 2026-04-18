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

	classifier Handle
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	localIPs   map[netip.Addr]struct{}
	servicePID uint32
	owners     *win.OwnerCache

	mu      sync.Mutex
	runners map[flowKey]*flowRunner
}

type flowKey struct {
	ip   netip.Addr
	port uint16
}

type flowRunner struct {
	mu       sync.Mutex
	flow     proxy.Flow
	handle   Handle
	lastSeen time.Time
	closed   bool
}

const (
	classifierFilter = "outbound and tcp and !loopback and !impostor and tcp.Syn and !tcp.Ack and !tcp.Rst"
	runnerMaxAge     = 45 * time.Second
	runnerGraceAge   = 8 * time.Second
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
	h, err := Open(classifierFilter, LayerNetwork, 200, 0)
	if err != nil {
		return err
	}
	e.classifier = h
	e.owners = win.NewOwnerCache(2 * time.Second)
	_ = e.owners.ForceRefresh()
	e.runners = map[flowKey]*flowRunner{}
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.wg.Add(2)
	go e.classifierLoop(ctx)
	go e.cleanup(ctx)
	if e.Monitor != nil {
		e.Monitor.AddLog("info", "WinDivert started in selective SYN-classifier mode")
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
	e.mu.Lock()
	for _, r := range e.runners {
		r.close()
	}
	e.runners = nil
	e.mu.Unlock()
	e.wg.Wait()
	return nil
}

func (e *Engine) classifierLoop(ctx context.Context) {
	defer e.wg.Done()
	buf := make([]byte, 0xFFFF)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		addr := &Address{}
		n, err := e.classifier.Recv(buf, addr)
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
			_, _ = e.classifier.Send(raw, addr)
			continue
		}
		if e.isLocal(pkt.Dst) {
			_, _ = e.classifier.Send(pkt.Raw, addr)
			continue
		}
		pid, exe, tries, ok := e.lookup(pkt)
		if !ok {
			if e.Monitor != nil {
				e.Monitor.AddLog("warn", "owner lookup failed for %s:%d -> %s:%d, passing direct", pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort)
			}
			_, _ = e.classifier.Send(pkt.Raw, addr)
			continue
		}
		if pid == e.servicePID {
			_, _ = e.classifier.Send(pkt.Raw, addr)
			continue
		}
		flow := proxy.Flow{PID: pid, ExePath: exe, ClientIP: pkt.Src, ClientPort: pkt.SrcPort, OriginalIP: pkt.Dst, OriginalPort: pkt.DstPort, IPv6: pkt.IPv6}
		plan := e.evaluatePlan(flow)
		if plan.Definitive && plan.Action == config.ActionDirect {
			_, _ = e.classifier.Send(pkt.Raw, addr)
			continue
		}
		if err := e.ensureRunner(ctx, flow); err != nil {
			if e.Monitor != nil {
				e.Monitor.AddLog("error", "flow runner start failed for %s:%d -> %s:%d: %v", pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort, err)
			}
			_, _ = e.classifier.Send(pkt.Raw, addr)
			continue
		}
		e.Flows.Register(flow)
		if e.Monitor != nil {
			e.Monitor.AddLog("debug", "intercepted pid=%d exe=%s %s:%d -> %s:%d after %d owner tries action=%s rule=%s", pid, exe, pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort, tries, plan.Action, plan.RuleName)
		}
		pkt.SetDst(flow.ClientIP, uint16(e.ListenerPort))
		_ = CalcChecksums(pkt.Raw, addr)
		_, _ = e.classifier.Send(pkt.Raw, addr)
	}
}

func (e *Engine) cleanup(ctx context.Context) {
	defer e.wg.Done()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now().UTC()
			e.Flows.Cleanup(2 * time.Minute)
			e.mu.Lock()
			for k, r := range e.runners {
				r.mu.Lock()
				idle := now.Sub(r.lastSeen)
				r.mu.Unlock()
				_, active := e.Flows.Lookup(r.flow.ClientIP, r.flow.ClientPort)
				if idle > runnerMaxAge || (!active && idle > runnerGraceAge) {
					r.close()
					delete(e.runners, k)
				}
			}
			e.mu.Unlock()
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

func (e *Engine) ensureRunner(ctx context.Context, flow proxy.Flow) error {
	k := flowKey{ip: flow.ClientIP.Unmap(), port: flow.ClientPort}
	e.mu.Lock()
	if existing, ok := e.runners[k]; ok {
		if existing.flow.OriginalIP == flow.OriginalIP && existing.flow.OriginalPort == flow.OriginalPort {
			existing.touch()
			e.mu.Unlock()
			return nil
		}
		existing.close()
		delete(e.runners, k)
	}
	filter := buildFlowFilter(flow, e.ListenerPort)
	h, err := Open(filter, LayerNetwork, 100, 0)
	if err != nil {
		e.mu.Unlock()
		return err
	}
	runner := &flowRunner{flow: flow, handle: h, lastSeen: time.Now().UTC()}
	e.runners[k] = runner
	e.wg.Add(1)
	go e.runnerLoop(ctx, runner)
	e.mu.Unlock()
	return nil
}

func (e *Engine) runnerLoop(ctx context.Context, runner *flowRunner) {
	defer e.wg.Done()
	buf := make([]byte, 0xFFFF)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		addr := &Address{}
		n, err := runner.handle.Recv(buf, addr)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if runner.isClosed() {
				return
			}
			if e.Monitor != nil {
				e.Monitor.AddLog("warn", "flow runner recv failed for %s:%d: %v", runner.flow.ClientIP, runner.flow.ClientPort, err)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		raw := buf[:n]
		pkt, err := ParsePacket(raw)
		if err != nil {
			_, _ = runner.handle.Send(raw, addr)
			continue
		}
		runner.touch()
		if pkt.Src == runner.flow.ClientIP && pkt.SrcPort == runner.flow.ClientPort && pkt.Dst == runner.flow.OriginalIP && pkt.DstPort == runner.flow.OriginalPort {
			pkt.SetDst(runner.flow.ClientIP, uint16(e.ListenerPort))
			_ = CalcChecksums(pkt.Raw, addr)
			e.Flows.Touch(runner.flow.ClientIP, runner.flow.ClientPort)
			_, _ = runner.handle.Send(pkt.Raw, addr)
			continue
		}
		if pkt.SrcPort == uint16(e.ListenerPort) && pkt.Dst == runner.flow.ClientIP && pkt.DstPort == runner.flow.ClientPort {
			pkt.SetSrc(runner.flow.OriginalIP, runner.flow.OriginalPort)
			_ = CalcChecksums(pkt.Raw, addr)
			e.Flows.Touch(runner.flow.ClientIP, runner.flow.ClientPort)
			_, _ = runner.handle.Send(pkt.Raw, addr)
			continue
		}
		_, _ = runner.handle.Send(pkt.Raw, addr)
	}
}

func buildFlowFilter(flow proxy.Flow, listenerPort int) string {
	clientIP := formatFilterAddr(flow.ClientIP)
	origIP := formatFilterAddr(flow.OriginalIP)
	return fmt.Sprintf(
		"outbound and tcp and !impostor and ((localAddr == %s and localPort == %d and remoteAddr == %s and remotePort == %d) or (tcp.SrcPort == %d and remoteAddr == %s and remotePort == %d))",
		clientIP, flow.ClientPort, origIP, flow.OriginalPort, listenerPort, clientIP, flow.ClientPort,
	)
}

func formatFilterAddr(ip netip.Addr) string {
	return ip.Unmap().String()
}

func (r *flowRunner) touch() {
	r.mu.Lock()
	r.lastSeen = time.Now().UTC()
	r.mu.Unlock()
}

func (r *flowRunner) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.handle != 0 {
		_ = r.handle.Close()
		r.handle = 0
	}
}

func (r *flowRunner) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}
