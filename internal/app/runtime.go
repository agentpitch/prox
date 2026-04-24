package app

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openai/pitchprox/internal/config"
	"github.com/openai/pitchprox/internal/monitor"
	"github.com/openai/pitchprox/internal/proxy"
	"github.com/openai/pitchprox/internal/rules"
	"github.com/openai/pitchprox/internal/win"
	"github.com/openai/pitchprox/internal/windivert"
)

type Runtime struct {
	store        *config.Store
	monitor      *monitor.Bus
	flows        *proxy.FlowTable
	mu           sync.RWMutex
	cfg          config.Config
	engine       *rules.Engine
	computerName string

	proxyServer         *proxy.Server
	divert              *windivert.Engine
	directObserver      *directObserver
	interceptionEnabled bool
	runCancel           context.CancelFunc
}

func NewRuntime(configPath string, historyPath string) (*Runtime, error) {
	st, err := config.NewStore(configPath)
	if err != nil {
		return nil, err
	}
	computerName, _ := os.Hostname()
	cfg := st.Get()
	eng, err := rules.Compile(cfg, computerName)
	if err != nil {
		return nil, err
	}
	bus, err := monitor.NewBus(historyPath)
	if err != nil {
		return nil, err
	}
	bus.SetRetentionWindow(time.Duration(cfg.RetentionMinutes) * time.Minute)
	return &Runtime{
		store:               st,
		monitor:             bus,
		flows:               proxy.NewFlowTable(),
		cfg:                 config.Clone(cfg),
		engine:              eng,
		computerName:        computerName,
		interceptionEnabled: !eng.AllEnabledActionsDirect(),
	}, nil
}

func (r *Runtime) Monitor() *monitor.Bus { return r.monitor }

func (r *Runtime) CurrentConfig() config.Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return config.Clone(r.cfg)
}

func (r *Runtime) WebUIURL() string {
	return "http://" + r.CurrentConfig().HTTP.Listen
}

func (r *Runtime) TrayView(seconds int) monitor.TrayView {
	return r.monitor.TrayView(seconds)
}

func (r *Runtime) UpdateConfig(cfg config.Config) error {
	cfg, err := config.Canonicalize(cfg)
	if err != nil {
		return err
	}
	eng, err := rules.Compile(cfg, r.computerName)
	if err != nil {
		return err
	}

	r.mu.RLock()
	old := config.Clone(r.cfg)
	oldInterception := r.interceptionEnabled
	r.mu.RUnlock()

	savedCfg, err := r.store.Save(cfg)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.cfg = config.Clone(savedCfg)
	r.engine = eng
	r.interceptionEnabled = !eng.AllEnabledActionsDirect()
	r.mu.Unlock()

	r.monitor.SetRetentionWindow(time.Duration(savedCfg.RetentionMinutes) * time.Minute)
	r.monitor.AddLog("info", "configuration updated")
	if old.HTTP.Listen != savedCfg.HTTP.Listen ||
		old.Transparent.ListenerPort != savedCfg.Transparent.ListenerPort ||
		old.Transparent.IPv4Listener != savedCfg.Transparent.IPv4Listener ||
		old.Transparent.IPv6Listener != savedCfg.Transparent.IPv6Listener {
		r.monitor.AddLog("warn", "listener changes require service restart to take effect")
	}
	if oldInterception != (!eng.AllEnabledActionsDirect()) {
		r.monitor.AddLog("warn", "interception mode changed; restart required to apply optimized fast-path mode")
	}
	return nil
}

func (r *Runtime) Start(ctx context.Context) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	r.runCancel = cancel
	defer func() {
		if err == nil {
			return
		}
		cancel()
		r.runCancel = nil
		if r.divert != nil {
			_ = r.divert.Close()
			r.divert = nil
		}
		if r.proxyServer != nil {
			_ = r.proxyServer.Close()
			r.proxyServer = nil
		}
	}()
	cfg := r.CurrentConfig()
	r.directObserver = &directObserver{
		Monitor:         r.monitor,
		Flows:           r.flows,
		ActiveInterval:  7 * time.Second,
		DormantInterval: 5 * time.Second,
		Decide:          r.directConnectionView,
	}
	go r.directObserver.Start(ctx)
	go startIdleMemoryTrimmer(ctx, r.monitor)

	if !r.interceptionEnabled {
		r.monitor.AddLog("info", "runtime started in optimized observer-only mode (all enabled rules are direct)")
		return nil
	}

	r.proxyServer = &proxy.Server{
		IPv4Addr:     cfg.Transparent.IPv4Listener,
		IPv6Addr:     cfg.Transparent.IPv6Listener,
		Port:         cfg.Transparent.ListenerPort,
		SniffBytes:   cfg.Transparent.SniffBytes,
		SniffTimeout: time.Duration(cfg.Transparent.SniffTimeout) * time.Millisecond,
		Flows:        r.flows,
		Route:        r.route,
		Monitor:      r.monitor,
	}
	if err := r.proxyServer.Start(ctx); err != nil {
		return fmt.Errorf("start transparent listener: %w", err)
	}
	r.divert = &windivert.Engine{
		ListenerPort: cfg.Transparent.ListenerPort,
		Flows:        r.flows,
		Monitor:      r.monitor,
		Plan:         r.planFlow,
	}
	if err := r.divert.Start(ctx); err != nil {
		return fmt.Errorf("start WinDivert engine: %w", err)
	}
	r.monitor.AddLog("info", "runtime started with selective interception fast-path")
	return nil
}

func (r *Runtime) TestProxy(pf config.ProxyProfile, target string) (proxy.ProxyTestResult, error) {
	result, err := proxy.TestProxyProfile(context.Background(), pf, target)
	if err != nil {
		return result, err
	}
	level := "info"
	if !result.OK {
		level = "warn"
	}
	name := strings.TrimSpace(pf.Name)
	if name == "" {
		name = pf.ID
	}
	if name == "" {
		name = pf.Address
	}
	r.monitor.AddLog(level, "proxy test [%s]: %s", name, result.Message)
	return result, nil
}

func (r *Runtime) Stop() error {
	if r.runCancel != nil {
		r.runCancel()
		r.runCancel = nil
	}
	if r.divert != nil {
		_ = r.divert.Close()
	}
	if r.proxyServer != nil {
		_ = r.proxyServer.Close()
	}
	if r.monitor != nil {
		_ = r.monitor.Close()
	}
	return nil
}

func (r *Runtime) route(flow proxy.Flow, sniff proxy.SniffResult) (proxy.RouteResult, config.Config, error) {
	r.mu.RLock()
	cfg := r.cfg
	eng := r.engine
	r.mu.RUnlock()

	dec := eng.Match(rules.Request{
		PID:        flow.PID,
		AppPath:    flow.ExePath,
		Hostname:   sniff.Hostname,
		TargetIP:   flow.OriginalIP,
		TargetPort: flow.OriginalPort,
	})
	if !dec.Matched {
		dec.Action = config.ActionDirect
	}
	return proxy.RouteResult{
		RuleID:   dec.RuleID,
		RuleName: dec.Rule,
		Action:   dec.Action,
		ProxyID:  dec.ProxyID,
		ChainID:  dec.ChainID,
		Hostname: sniff.Hostname,
	}, cfg, nil
}

func (r *Runtime) planFlow(flow proxy.Flow) windivert.PlanDecision {
	r.mu.RLock()
	eng := r.engine
	r.mu.RUnlock()
	pre := eng.Preflight(rules.Request{
		PID:        flow.PID,
		AppPath:    flow.ExePath,
		TargetIP:   flow.OriginalIP,
		TargetPort: flow.OriginalPort,
	})
	return windivert.PlanDecision{
		Definitive:    pre.Definitive,
		NeedsHostname: pre.NeedsHostname,
		RuleID:        pre.RuleID,
		RuleName:      pre.Rule,
		Action:        pre.Action,
		ProxyID:       pre.ProxyID,
		ChainID:       pre.ChainID,
	}
}

func (r *Runtime) directConnectionView(item win.TCPConnection) (monitor.Connection, bool) {
	r.mu.RLock()
	eng := r.engine
	interceptionEnabled := r.interceptionEnabled
	r.mu.RUnlock()

	pre := eng.Preflight(rules.Request{
		PID:        item.PID,
		AppPath:    item.ExePath,
		TargetIP:   item.RemoteIP,
		TargetPort: item.RemotePort,
	})
	if interceptionEnabled && (!pre.Definitive || pre.Action != config.ActionDirect) {
		return monitor.Connection{}, false
	}
	action := pre.Action
	if action == "" {
		action = config.ActionDirect
	}
	return monitor.Connection{
		ID:           monitor.ConnID(item.PID, item.LocalIP, item.LocalPort, item.RemoteIP, item.RemotePort),
		PID:          item.PID,
		ExePath:      item.ExePath,
		SourceIP:     item.LocalIP.String(),
		SourcePort:   item.LocalPort,
		OriginalIP:   item.RemoteIP.String(),
		OriginalPort: item.RemotePort,
		RuleID:       pre.RuleID,
		RuleName:     pre.Rule,
		Action:       action,
		State:        "open",
		CreatedAt:    item.SeenAt,
		Count:        1,
	}, true
}
