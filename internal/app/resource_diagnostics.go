package app

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openai/pitchprox/internal/monitor"
)

type resourceDiagnosticsConfig struct {
	Path            string
	Interval        time.Duration
	ProfileDir      string
	ProfileInterval time.Duration
	ProfileKeep     int
	ProfileGC       bool
	HandleTypes     time.Duration
}

type resourceSample struct {
	Event         string                 `json:"event"`
	Time          time.Time              `json:"time"`
	UptimeSeconds float64                `json:"uptime_seconds"`
	PID           int                    `json:"pid"`
	UIActive      bool                   `json:"ui_active"`
	Goroutines    int                    `json:"goroutines"`
	Go            resourceGoStats        `json:"go"`
	OS            resourceOSStats        `json:"os"`
	App           resourceAppStats       `json:"app"`
	Profiles      []string               `json:"profiles,omitempty"`
	Delta         map[string]interface{} `json:"delta,omitempty"`
	Error         string                 `json:"error,omitempty"`
}

type resourceAppStats struct {
	InterceptionEnabled bool                    `json:"interception_enabled"`
	RuntimeRunning      bool                    `json:"runtime_running"`
	FlowTableLen        int                     `json:"flow_table_len"`
	Monitor             monitor.DiagnosticStats `json:"monitor"`
}

type resourceGoStats struct {
	AllocBytes        uint64  `json:"alloc_bytes"`
	TotalAllocBytes   uint64  `json:"total_alloc_bytes"`
	SysBytes          uint64  `json:"sys_bytes"`
	HeapAllocBytes    uint64  `json:"heap_alloc_bytes"`
	HeapSysBytes      uint64  `json:"heap_sys_bytes"`
	HeapIdleBytes     uint64  `json:"heap_idle_bytes"`
	HeapInuseBytes    uint64  `json:"heap_inuse_bytes"`
	HeapReleasedBytes uint64  `json:"heap_released_bytes"`
	HeapObjects       uint64  `json:"heap_objects"`
	StackInuseBytes   uint64  `json:"stack_inuse_bytes"`
	StackSysBytes     uint64  `json:"stack_sys_bytes"`
	MSpanInuseBytes   uint64  `json:"mspan_inuse_bytes"`
	MCacheInuseBytes  uint64  `json:"mcache_inuse_bytes"`
	OtherSysBytes     uint64  `json:"other_sys_bytes"`
	NextGCBytes       uint64  `json:"next_gc_bytes"`
	LastGCUnixNano    uint64  `json:"last_gc_unix_nano"`
	NumGC             uint32  `json:"num_gc"`
	PauseTotalNs      uint64  `json:"pause_total_ns"`
	LastPauseNs       uint64  `json:"last_pause_ns"`
	GCCPUFraction     float64 `json:"gc_cpu_fraction"`
	Mallocs           uint64  `json:"mallocs"`
	Frees             uint64  `json:"frees"`
	LiveObjects       uint64  `json:"live_objects"`
}

func resourceDiagnosticsFromEnv() (resourceDiagnosticsConfig, bool) {
	diagnosticDefaults := resourceDiagnosticsDefaultsEnabled()
	raw := strings.TrimSpace(os.Getenv("PITCHPROX_RESOURCE_LOG"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("PITCHPROX_DIAG_RESOURCE_LOG"))
	}
	if isDisabledEnvValue(raw) {
		return resourceDiagnosticsConfig{}, false
	}
	if raw == "" && diagnosticDefaults {
		raw = "default"
	}
	if raw == "" {
		return resourceDiagnosticsConfig{}, false
	}
	path := raw
	if isEnabledEnvValue(raw) {
		path = defaultResourceDiagnosticsPath()
	}
	intervalFallback := 30 * time.Second
	profileKeepFallback := 144
	handleTypesFallback := time.Duration(0)
	if diagnosticDefaults {
		intervalFallback = 15 * time.Second
		profileKeepFallback = 24
		handleTypesFallback = 10 * time.Minute
	}
	interval := parseResourceDiagnosticsInterval(os.Getenv("PITCHPROX_RESOURCE_LOG_INTERVAL"), intervalFallback)
	profileInterval := parseResourceDiagnosticsOptionalInterval(os.Getenv("PITCHPROX_RESOURCE_PROFILE_INTERVAL"), 10*time.Minute)
	profileDir := strings.TrimSpace(os.Getenv("PITCHPROX_RESOURCE_PROFILE_DIR"))
	if profileDir == "" {
		profileDir = defaultResourceProfileDir(path)
	}
	return resourceDiagnosticsConfig{
		Path:            path,
		Interval:        interval,
		ProfileDir:      profileDir,
		ProfileInterval: profileInterval,
		ProfileKeep:     parseResourceDiagnosticsInt(os.Getenv("PITCHPROX_RESOURCE_PROFILE_KEEP"), profileKeepFallback),
		ProfileGC:       parseResourceDiagnosticsBool(os.Getenv("PITCHPROX_RESOURCE_PROFILE_GC"), false),
		HandleTypes:     parseResourceDiagnosticsOptionalInterval(os.Getenv("PITCHPROX_RESOURCE_HANDLE_TYPES_INTERVAL"), handleTypesFallback),
	}, true
}

func resourceDiagnosticsDefaultsEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("PITCHPROX_RESOURCE_DIAGNOSTIC_DEFAULTS"))
	if raw != "" {
		return isEnabledEnvValue(raw)
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(filepath.Base(exe)), "diagnostic")
}

func isEnabledEnvValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "default":
		return true
	default:
		return false
	}
}

func isDisabledEnvValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off", "disabled":
		return true
	default:
		return false
	}
}

func defaultResourceDiagnosticsPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "pitchProx.resources.jsonl")
	}
	return filepath.Join(os.TempDir(), "pitchProx.resources.jsonl")
}

func defaultResourceProfileDir(logPath string) string {
	ext := filepath.Ext(logPath)
	if ext == "" {
		return logPath + ".profiles"
	}
	return strings.TrimSuffix(logPath, ext) + ".profiles"
}

func parseResourceDiagnosticsInterval(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if d, err := time.ParseDuration(raw); err == nil && d >= time.Second {
		return d
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 1 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

func parseResourceDiagnosticsOptionalInterval(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if raw == "0" || isDisabledEnvValue(raw) {
		return 0
	}
	return parseResourceDiagnosticsInterval(raw, fallback)
}

func parseResourceDiagnosticsInt(raw string, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return fallback
	}
	return v
}

func parseResourceDiagnosticsBool(raw string, fallback bool) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if isEnabledEnvValue(raw) {
		return true
	}
	if isDisabledEnvValue(raw) {
		return false
	}
	return fallback
}

func startResourceDiagnostics(ctx context.Context, rt *Runtime) {
	cfg, ok := resourceDiagnosticsFromEnv()
	if !ok {
		return
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o755); err != nil {
		if rt != nil && rt.monitor != nil {
			rt.monitor.AddLog("warn", "resource diagnostics disabled: create log dir: %v", err)
		}
		return
	}
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		if rt != nil && rt.monitor != nil {
			rt.monitor.AddLog("warn", "resource diagnostics disabled: open log: %v", err)
		}
		return
	}
	if rt != nil && rt.monitor != nil {
		rt.monitor.AddLog("info", "resource diagnostics enabled: %s interval=%s profile_interval=%s", cfg.Path, cfg.Interval, cfg.ProfileInterval)
	}

	writer := bufio.NewWriterSize(f, 16*1024)
	enc := json.NewEncoder(writer)
	start := time.Now().UTC()
	startSample := collectResourceSample("start", start, rt, nil, false)
	if err := writeResourceSample(enc, writer, startSample); err != nil {
		_ = f.Close()
		appendResourceDiagnosticsError(cfg.Path, "initial JSONL write failed: %v", err)
		if rt != nil && rt.monitor != nil {
			rt.monitor.AddLog("warn", "resource diagnostics disabled: initial log write failed: %v", err)
		}
		return
	}
	if err := f.Sync(); err != nil {
		appendResourceDiagnosticsError(cfg.Path, "initial JSONL sync failed: %v", err)
	}
	if err := writeResourceDiagnosticsManifest(cfg, start); err != nil {
		appendResourceDiagnosticsError(cfg.Path, "manifest write failed: %v", err)
	}
	go runResourceDiagnostics(ctx, rt, f, writer, enc, cfg, start, &startSample)
}

func runResourceDiagnostics(ctx context.Context, rt *Runtime, f *os.File, writer *bufio.Writer, enc *json.Encoder, cfg resourceDiagnosticsConfig, start time.Time, prev *resourceSample) {
	defer f.Close()
	defer func() {
		if err := writer.Flush(); err != nil {
			appendResourceDiagnosticsError(cfg.Path, "final JSONL flush failed: %v", err)
		}
	}()
	nextProfile := start.Add(cfg.ProfileInterval)
	nextHandleTypes := start.Add(cfg.HandleTypes)
	write := func(event string) bool {
		now := time.Now().UTC()
		var profileErr error
		var profiles []string
		if cfg.ProfileInterval > 0 && !now.Before(nextProfile) {
			profiles, profileErr = writeResourceProfiles(cfg.ProfileDir, now, cfg.ProfileGC, cfg.ProfileKeep)
			nextProfile = now.Add(cfg.ProfileInterval)
		}
		includeHandleTypes := false
		if cfg.HandleTypes > 0 && !now.Before(nextHandleTypes) {
			includeHandleTypes = true
			nextHandleTypes = now.Add(cfg.HandleTypes)
		}
		sample := collectResourceSample(event, start, rt, prev, includeHandleTypes)
		sample.Profiles = profiles
		if profileErr != nil {
			sample.Error = appendResourceError(sample.Error, fmt.Errorf("write resource profiles: %w", profileErr))
		}
		if err := writeResourceSample(enc, writer, sample); err != nil {
			appendResourceDiagnosticsError(cfg.Path, "JSONL write failed: %v", err)
			if rt != nil && rt.monitor != nil {
				rt.monitor.AddLog("warn", "resource diagnostics stopped: log write failed: %v", err)
			}
			return false
		}
		prev = &sample
		return true
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = write("stop")
			return
		case <-ticker.C:
			if !write("sample") {
				return
			}
		}
	}
}

func writeResourceSample(enc *json.Encoder, writer *bufio.Writer, sample resourceSample) error {
	if err := enc.Encode(sample); err != nil {
		return err
	}
	return writer.Flush()
}

type resourceDiagnosticsManifest struct {
	Event                 string        `json:"event"`
	Time                  time.Time     `json:"time"`
	PID                   int           `json:"pid"`
	Executable            string        `json:"executable"`
	WorkingDirectory      string        `json:"working_directory"`
	LogPath               string        `json:"log_path"`
	ProfileDir            string        `json:"profile_dir"`
	Interval              time.Duration `json:"interval_ns"`
	ProfileInterval       time.Duration `json:"profile_interval_ns"`
	ProfileKeep           int           `json:"profile_keep"`
	ProfileGC             bool          `json:"profile_gc"`
	HandleTypesInterval   time.Duration `json:"handle_types_interval_ns"`
	DiagnosticDefaults    bool          `json:"diagnostic_defaults"`
	DiagnosticDefaultsWhy string        `json:"diagnostic_defaults_why,omitempty"`
}

func writeResourceDiagnosticsManifest(cfg resourceDiagnosticsConfig, start time.Time) error {
	exe, _ := os.Executable()
	wd, _ := os.Getwd()
	base := ""
	if exe != "" {
		base = filepath.Base(exe)
	}
	manifest := resourceDiagnosticsManifest{
		Event:               "resource_diagnostics_manifest",
		Time:                start,
		PID:                 os.Getpid(),
		Executable:          exe,
		WorkingDirectory:    wd,
		LogPath:             cfg.Path,
		ProfileDir:          cfg.ProfileDir,
		Interval:            cfg.Interval,
		ProfileInterval:     cfg.ProfileInterval,
		ProfileKeep:         cfg.ProfileKeep,
		ProfileGC:           cfg.ProfileGC,
		HandleTypesInterval: cfg.HandleTypes,
		DiagnosticDefaults:  resourceDiagnosticsDefaultsEnabled(),
	}
	if strings.Contains(strings.ToLower(base), "diagnostic") {
		manifest.DiagnosticDefaultsWhy = "executable name contains diagnostic"
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	path := strings.TrimSuffix(cfg.Path, filepath.Ext(cfg.Path)) + ".manifest.json"
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func collectResourceSample(event string, start time.Time, rt *Runtime, prev *resourceSample, includeHandleTypes bool) resourceSample {
	now := time.Now().UTC()
	stats := runtime.MemStats{}
	runtime.ReadMemStats(&stats)
	osStats, err := readResourceOSStats(includeHandleTypes)
	sample := resourceSample{
		Event:         event,
		Time:          now,
		UptimeSeconds: now.Sub(start).Seconds(),
		PID:           os.Getpid(),
		Goroutines:    runtime.NumGoroutine(),
		Go: resourceGoStats{
			AllocBytes:        stats.Alloc,
			TotalAllocBytes:   stats.TotalAlloc,
			SysBytes:          stats.Sys,
			HeapAllocBytes:    stats.HeapAlloc,
			HeapSysBytes:      stats.HeapSys,
			HeapIdleBytes:     stats.HeapIdle,
			HeapInuseBytes:    stats.HeapInuse,
			HeapReleasedBytes: stats.HeapReleased,
			HeapObjects:       stats.HeapObjects,
			StackInuseBytes:   stats.StackInuse,
			StackSysBytes:     stats.StackSys,
			MSpanInuseBytes:   stats.MSpanInuse,
			MCacheInuseBytes:  stats.MCacheInuse,
			OtherSysBytes:     stats.OtherSys,
			NextGCBytes:       stats.NextGC,
			LastGCUnixNano:    stats.LastGC,
			NumGC:             stats.NumGC,
			PauseTotalNs:      stats.PauseTotalNs,
			GCCPUFraction:     stats.GCCPUFraction,
			Mallocs:           stats.Mallocs,
			Frees:             stats.Frees,
			LiveObjects:       stats.Mallocs - stats.Frees,
		},
		OS: osStats,
	}
	if stats.NumGC > 0 {
		sample.Go.LastPauseNs = stats.PauseNs[(stats.NumGC+255)%256]
	}
	if rt != nil {
		sample.App = rt.resourceDiagnosticsStats()
		sample.UIActive = sample.App.Monitor.UIActive
	}
	if err != nil {
		sample.Error = err.Error()
	}
	if prev != nil {
		sample.Delta = resourceSampleDelta(prev, &sample)
	}
	return sample
}

func (r *Runtime) resourceDiagnosticsStats() resourceAppStats {
	if r == nil {
		return resourceAppStats{}
	}
	r.runMu.RLock()
	running := r.running
	flows := r.flows
	r.runMu.RUnlock()
	var flowLen int
	if flows != nil {
		flowLen = flows.Len()
	}
	r.mu.RLock()
	interceptionEnabled := r.interceptionEnabled
	r.mu.RUnlock()
	var monitorStats monitor.DiagnosticStats
	if r.monitor != nil {
		monitorStats = r.monitor.DiagnosticStats()
	}
	return resourceAppStats{
		InterceptionEnabled: interceptionEnabled,
		RuntimeRunning:      running,
		FlowTableLen:        flowLen,
		Monitor:             monitorStats,
	}
}

func resourceSampleDelta(prev, current *resourceSample) map[string]interface{} {
	return map[string]interface{}{
		"seconds":                  current.Time.Sub(prev.Time).Seconds(),
		"os_private_bytes":         int64(current.OS.PrivateBytes) - int64(prev.OS.PrivateBytes),
		"os_working_set_bytes":     int64(current.OS.WorkingSetBytes) - int64(prev.OS.WorkingSetBytes),
		"os_handle_count":          int64(current.OS.HandleCount) - int64(prev.OS.HandleCount),
		"os_gdi_handle_count":      int64(current.OS.GDIHandleCount) - int64(prev.OS.GDIHandleCount),
		"os_user_handle_count":     int64(current.OS.UserHandleCount) - int64(prev.OS.UserHandleCount),
		"go_heap_alloc_bytes":      int64(current.Go.HeapAllocBytes) - int64(prev.Go.HeapAllocBytes),
		"go_heap_released_bytes":   int64(current.Go.HeapReleasedBytes) - int64(prev.Go.HeapReleasedBytes),
		"go_heap_objects":          int64(current.Go.HeapObjects) - int64(prev.Go.HeapObjects),
		"go_live_objects":          int64(current.Go.LiveObjects) - int64(prev.Go.LiveObjects),
		"go_num_gc":                int64(current.Go.NumGC) - int64(prev.Go.NumGC),
		"goroutines":               int64(current.Goroutines) - int64(prev.Goroutines),
		"os_user_time_ms":          int64(current.OS.UserTimeMs) - int64(prev.OS.UserTimeMs),
		"os_kernel_time_ms":        int64(current.OS.KernelTimeMs) - int64(prev.OS.KernelTimeMs),
		"os_write_transfer_bytes":  int64(current.OS.WriteTransferBytes) - int64(prev.OS.WriteTransferBytes),
		"os_read_transfer_bytes":   int64(current.OS.ReadTransferBytes) - int64(prev.OS.ReadTransferBytes),
		"os_write_operation_count": int64(current.OS.WriteOperationCount) - int64(prev.OS.WriteOperationCount),
		"os_read_operation_count":  int64(current.OS.ReadOperationCount) - int64(prev.OS.ReadOperationCount),
		"app_flow_table_len":       int64(current.App.FlowTableLen) - int64(prev.App.FlowTableLen),
		"monitor_active":           int64(current.App.Monitor.ActiveConnections) - int64(prev.App.Monitor.ActiveConnections),
		"monitor_traffic_buckets":  int64(current.App.Monitor.TrafficLiveBuckets) - int64(prev.App.Monitor.TrafficLiveBuckets),
		"monitor_subscribers":      int64(current.App.Monitor.Subscribers) - int64(prev.App.Monitor.Subscribers),
		"history_pending_logs":     int64(current.App.Monitor.History.PendingLogs) - int64(prev.App.Monitor.History.PendingLogs),
		"history_pending_conns":    int64(current.App.Monitor.History.PendingConnections) - int64(prev.App.Monitor.History.PendingConnections),
		"history_pending_traffic":  int64(current.App.Monitor.History.PendingTrafficBuckets) - int64(prev.App.Monitor.History.PendingTrafficBuckets),
		"history_pending_rules":    int64(current.App.Monitor.History.PendingRuleBuckets) - int64(prev.App.Monitor.History.PendingRuleBuckets),
	}
}

func writeResourceProfiles(dir string, now time.Time, forceGC bool, keep int) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if forceGC {
		runtime.GC()
	}
	stamp := now.UTC().Format("20060102-150405")
	files := []struct {
		name  string
		write func(io.Writer) error
	}{
		{name: "heap-" + stamp + ".pprof", write: pprof.WriteHeapProfile},
		{name: "goroutine-" + stamp + ".pprof", write: func(w io.Writer) error {
			profile := pprof.Lookup("goroutine")
			if profile == nil {
				return nil
			}
			return profile.WriteTo(w, 2)
		}},
	}
	out := make([]string, 0, len(files))
	for _, item := range files {
		path := filepath.Join(dir, item.name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return out, err
		}
		writeErr := item.write(f)
		closeErr := f.Close()
		if writeErr != nil {
			return out, writeErr
		}
		if closeErr != nil {
			return out, closeErr
		}
		out = append(out, path)
	}
	if err := pruneResourceProfiles(dir, keep); err != nil {
		return out, err
	}
	return out, nil
}

func pruneResourceProfiles(dir string, keep int) error {
	if keep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type profileFile struct {
		name string
		mod  time.Time
	}
	files := make([]profileFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".pprof") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, profileFile{name: entry.Name(), mod: info.ModTime()})
	}
	if len(files) <= keep {
		return nil
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].mod.Before(files[j].mod)
	})
	for _, item := range files[:len(files)-keep] {
		if err := os.Remove(filepath.Join(dir, item.name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func appendResourceError(existing string, err error) string {
	if err == nil {
		return existing
	}
	if existing == "" {
		return err.Error()
	}
	return existing + "; " + err.Error()
}

func appendResourceDiagnosticsError(logPath string, format string, args ...interface{}) {
	if logPath == "" {
		return
	}
	path := strings.TrimSuffix(logPath, filepath.Ext(logPath)) + ".errors.log"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), fmt.Sprintf(format, args...))
}
