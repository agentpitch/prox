package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/monitor"
	"github.com/agentpitch/prox/internal/proxy"
	"github.com/agentpitch/prox/internal/rules"
	"github.com/agentpitch/prox/internal/util"
	"github.com/agentpitch/prox/internal/win"
	"github.com/agentpitch/prox/internal/windivert"
)

type Runtime struct {
	store   *config.Store
	monitor *monitor.Bus
	flows   *proxy.FlowTable
	// transitionMu serializes config activation with every runtime lifecycle
	// transition. It must be acquired before runMu and never while mu is held.
	transitionMu sync.Mutex
	mu           sync.RWMutex
	cfg          config.Config
	engine       *rules.Engine
	computerName string

	proxyServer         *proxy.Server
	divert              *windivert.Engine
	directObserver      *directObserver
	interceptionEnabled bool

	runMu              sync.RWMutex
	rootCtx            context.Context
	runCancel          context.CancelFunc
	runWG              sync.WaitGroup
	running            bool
	closed             bool
	diagnosticsCancel  context.CancelFunc
	diagnosticsOnce    sync.Once
	listTCPConnections func() ([]win.TCPConnection, error)
	tcpSnapshotter     *win.TCPSnapshotter
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
	bus.SetDroppedLogMaxBytes(cfg.DroppedLogMaxBytes)
	return &Runtime{
		store:               st,
		monitor:             bus,
		flows:               proxy.NewFlowTable(),
		cfg:                 config.Clone(cfg),
		engine:              eng,
		computerName:        computerName,
		interceptionEnabled: !eng.AllEnabledActionsDirect(),
		tcpSnapshotter:      win.NewTCPSnapshotter(),
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
	return r.UpdateConfigIfCurrent(cfg, time.Time{})
}

func (r *Runtime) UpdateConfigIfCurrent(cfg config.Config, expectedUpdatedAt time.Time) error {
	r.transitionMu.Lock()
	defer r.transitionMu.Unlock()
	return r.updateConfigIfCurrentTransitionLocked(cfg, expectedUpdatedAt)
}

func (r *Runtime) updateConfigIfCurrentTransitionLocked(cfg config.Config, expectedUpdatedAt time.Time) error {
	r.mu.RLock()
	old := config.Clone(r.cfg)
	oldEngine := r.engine
	oldInterception := r.interceptionEnabled
	r.mu.RUnlock()
	if !expectedUpdatedAt.IsZero() && !expectedUpdatedAt.Equal(old.UpdatedAt) {
		return fmt.Errorf(
			"%w: expected updated_at %s, current %s",
			config.ErrConfigConflict,
			expectedUpdatedAt.UTC().Format(time.RFC3339Nano),
			old.UpdatedAt.UTC().Format(time.RFC3339Nano),
		)
	}

	cfg, err := config.Canonicalize(cfg)
	if err != nil {
		return err
	}
	eng, err := rules.Compile(cfg, r.computerName)
	if err != nil {
		return err
	}

	newInterception := !eng.AllEnabledActionsDirect()
	restart := runtimeRestartRequired(old, cfg, oldInterception, newInterception) && r.Running()

	if restart {
		r.applyConfigInMemory(cfg, eng, newInterception)
		r.applyConfigToMonitor(cfg)
		r.monitor.AddLog("info", "runtime restart applying routing/listener changes")
		if err := r.restartTransitionLocked(); err != nil {
			r.applyConfigInMemory(old, oldEngine, oldInterception)
			r.applyConfigToMonitor(old)
			rollbackErr := r.startAfterFailedRestartTransitionLocked()
			r.monitor.AddLog("error", "runtime restart failed, restored previous configuration: %v", err)
			if rollbackErr != nil {
				return errors.Join(err, fmt.Errorf("restart previous configuration: %w", rollbackErr))
			}
			return err
		}
	}

	savedCfg, err := r.store.Save(cfg)
	if err != nil {
		if restart {
			r.applyConfigInMemory(old, oldEngine, oldInterception)
			r.applyConfigToMonitor(old)
			rollbackErr := r.restartTransitionLocked()
			if rollbackErr != nil {
				return errors.Join(err, fmt.Errorf("rollback runtime after config save failure: %w", rollbackErr))
			}
		}
		return err
	}
	r.applyConfigInMemory(savedCfg, eng, newInterception)
	r.applyConfigToMonitor(savedCfg)
	if old.HTTP.Listen != savedCfg.HTTP.Listen {
		r.monitor.AddLog("warn", "HTTP listener changes require service restart to take effect")
	}
	r.monitor.AddLog("info", "configuration updated")
	return nil
}

func (r *Runtime) applyConfigInMemory(cfg config.Config, eng *rules.Engine, interception bool) {
	r.mu.Lock()
	r.cfg = config.Clone(cfg)
	r.engine = eng
	r.interceptionEnabled = interception
	r.mu.Unlock()
}

func (r *Runtime) applyConfigToMonitor(cfg config.Config) {
	r.monitor.SetRetentionWindow(time.Duration(cfg.RetentionMinutes) * time.Minute)
	r.monitor.SetDroppedLogMaxBytes(cfg.DroppedLogMaxBytes)
}

func (r *Runtime) startAfterFailedRestartTransitionLocked() error {
	r.runMu.RLock()
	ctx := r.rootCtx
	closed := r.closed
	r.runMu.RUnlock()
	if closed {
		return fmt.Errorf("runtime is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return r.startTransitionLocked(ctx)
}

func (r *Runtime) Running() bool {
	r.runMu.RLock()
	defer r.runMu.RUnlock()
	return r.running
}

func (r *Runtime) Start(ctx context.Context) (err error) {
	r.transitionMu.Lock()
	defer r.transitionMu.Unlock()
	return r.startTransitionLocked(ctx)
}

func (r *Runtime) startTransitionLocked(ctx context.Context) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	r.runMu.RLock()
	closed := r.closed
	r.runMu.RUnlock()
	if closed {
		return fmt.Errorf("runtime is closed")
	}
	r.diagnosticsOnce.Do(func() {
		diagCtx, diagCancel := context.WithCancel(ctx)
		r.runMu.Lock()
		r.diagnosticsCancel = diagCancel
		r.runMu.Unlock()
		startResourceDiagnostics(diagCtx, r)
	})

	r.runMu.Lock()
	defer r.runMu.Unlock()
	if r.closed {
		return fmt.Errorf("runtime is closed")
	}
	if r.running {
		return nil
	}
	r.rootCtx = ctx
	ctx, cancel := context.WithCancel(ctx)
	r.runCancel = cancel
	r.flows = proxy.NewFlowTable()
	flows := r.flows
	defer func() {
		if err == nil {
			return
		}
		_ = r.stopActiveLocked()
	}()
	cfg := r.CurrentConfig()
	r.mu.RLock()
	interceptionEnabled := r.interceptionEnabled
	r.mu.RUnlock()
	tcpSnapshotter := r.tcpSnapshotter
	if tcpSnapshotter == nil {
		tcpSnapshotter = win.NewTCPSnapshotter()
		r.tcpSnapshotter = tcpSnapshotter
	}
	listTCPConnections := r.listTCPConnections
	if listTCPConnections == nil {
		listTCPConnections = tcpSnapshotter.ListTCPConnections
	}
	r.directObserver = &directObserver{
		Monitor:         r.monitor,
		Flows:           flows,
		ActiveInterval:  10 * time.Second,
		DormantInterval: 5 * time.Second,
		Decide:          r.directConnectionView,
		List:            listTCPConnections,
		ReleaseDormant:  tcpSnapshotter.Clear,
	}
	r.runWG.Add(2)
	go func(observer *directObserver) {
		defer r.runWG.Done()
		observer.Start(ctx)
	}(r.directObserver)
	go func() {
		defer r.runWG.Done()
		startIdleMemoryTrimmer(ctx, r.monitor)
	}()

	if !interceptionEnabled {
		r.running = true
		r.monitor.AddLog("info", "runtime started in optimized observer-only mode (all enabled rules are direct)")
		return nil
	}

	r.proxyServer = &proxy.Server{
		IPv4Addr:     cfg.Transparent.IPv4Listener,
		IPv6Addr:     cfg.Transparent.IPv6Listener,
		Port:         cfg.Transparent.ListenerPort,
		SniffBytes:   cfg.Transparent.SniffBytes,
		SniffTimeout: time.Duration(cfg.Transparent.SniffTimeout) * time.Millisecond,
		Flows:        flows,
		Route:        r.route,
		Monitor:      r.monitor,
	}
	if err := r.proxyServer.Start(ctx); err != nil {
		return fmt.Errorf("start transparent listener: %w", err)
	}
	r.divert = &windivert.Engine{
		ListenerPort: cfg.Transparent.ListenerPort,
		Flows:        flows,
		Monitor:      r.monitor,
		Plan:         r.planFlow,
	}
	if err := r.divert.Start(ctx); err != nil {
		return fmt.Errorf("start WinDivert engine: %w", err)
	}
	r.running = true
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
	r.transitionMu.Lock()
	defer r.transitionMu.Unlock()
	return r.stopTransitionLocked()
}

func (r *Runtime) stopTransitionLocked() error {
	r.runMu.Lock()
	if r.closed {
		r.runMu.Unlock()
		return nil
	}
	r.closed = true
	if r.diagnosticsCancel != nil {
		r.diagnosticsCancel()
		r.diagnosticsCancel = nil
	}
	err := r.stopActiveLocked()
	r.rootCtx = nil
	r.runMu.Unlock()
	if r.monitor != nil {
		r.monitor.DisableUI()
		r.monitor.CloseActiveConnections()
		if closeErr := r.monitor.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

func (r *Runtime) Pause() error {
	r.transitionMu.Lock()
	defer r.transitionMu.Unlock()
	return r.pauseTransitionLocked()
}

func (r *Runtime) pauseTransitionLocked() error {
	r.runMu.Lock()
	if r.closed {
		r.runMu.Unlock()
		return fmt.Errorf("runtime is closed")
	}
	err := r.stopActiveLocked()
	r.runMu.Unlock()
	if r.monitor != nil {
		r.monitor.DisableUI()
		r.monitor.CloseActiveConnections()
	}
	util.ReleaseIdleMemory()
	return err
}

func (r *Runtime) Restart() error {
	r.transitionMu.Lock()
	defer r.transitionMu.Unlock()
	return r.restartTransitionLocked()
}

func (r *Runtime) restartTransitionLocked() error {
	r.runMu.Lock()
	if r.closed {
		r.runMu.Unlock()
		return fmt.Errorf("runtime is closed")
	}
	if !r.running {
		r.runMu.Unlock()
		return nil
	}
	ctx := r.rootCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.stopActiveLocked(); err != nil {
		r.runMu.Unlock()
		return err
	}
	r.runMu.Unlock()
	return r.startTransitionLocked(ctx)
}

func (r *Runtime) stopActiveLocked() error {
	var firstErr error
	if r.runCancel != nil {
		r.runCancel()
		r.runCancel = nil
	}
	if r.divert != nil {
		if err := r.divert.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		r.divert = nil
	}
	if r.proxyServer != nil {
		if err := r.proxyServer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		r.proxyServer = nil
	}
	r.runWG.Wait()
	r.directObserver = nil
	r.flows = proxy.NewFlowTable()
	r.running = false
	return firstErr
}

func runtimeRestartRequired(oldCfg, newCfg config.Config, oldInterception, newInterception bool) bool {
	return oldInterception != newInterception ||
		oldCfg.Transparent.ListenerPort != newCfg.Transparent.ListenerPort ||
		oldCfg.Transparent.IPv4Listener != newCfg.Transparent.IPv4Listener ||
		oldCfg.Transparent.IPv6Listener != newCfg.Transparent.IPv6Listener ||
		oldCfg.Transparent.SniffBytes != newCfg.Transparent.SniffBytes ||
		oldCfg.Transparent.SniffTimeout != newCfg.Transparent.SniffTimeout
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
		RuleMatch: monitor.RuleConditionMatch{
			Application: dec.Match.Application,
			Host:        dec.Match.Host,
			Port:        dec.Match.Port,
			Source:      monitor.RuleConditionSourceIntercepted,
		},
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

func (r *Runtime) directConnectionView(item win.TCPConnection) (monitor.Connection, monitor.RuleConditionMatch, bool) {
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
		return monitor.Connection{}, monitor.RuleConditionMatch{}, false
	}
	action := pre.Action
	if action == "" {
		action = config.ActionDirect
	}
	connection := monitor.Connection{
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
	}
	var ruleMatch monitor.RuleConditionMatch
	if pre.MatchDefinitive && pre.Matched && pre.Match.Application != "" && pre.Match.Host != "" && pre.Match.Port != "" {
		ruleMatch = monitor.RuleConditionMatch{
			Application: pre.Match.Application,
			Host:        pre.Match.Host,
			Port:        pre.Match.Port,
			Source:      monitor.RuleConditionSourceDirectObserver,
		}
	}
	return connection, ruleMatch, true
}
