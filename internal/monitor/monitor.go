package monitor

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openai/pitchprox/internal/config"
	"github.com/openai/pitchprox/internal/history"
)

type Connection struct {
	ID            string            `json:"id"`
	PID           uint32            `json:"pid"`
	ExePath       string            `json:"exe_path"`
	SourceIP      string            `json:"source_ip"`
	SourcePort    uint16            `json:"source_port"`
	OriginalIP    string            `json:"original_ip"`
	OriginalPort  uint16            `json:"original_port"`
	Hostname      string            `json:"hostname,omitempty"`
	RuleID        string            `json:"rule_id,omitempty"`
	RuleName      string            `json:"rule_name,omitempty"`
	Action        config.RuleAction `json:"action"`
	ProxyID       string            `json:"proxy_id,omitempty"`
	ChainID       string            `json:"chain_id,omitempty"`
	State         string            `json:"state"`
	BytesUp       int64             `json:"bytes_up"`
	BytesDown     int64             `json:"bytes_down"`
	CreatedAt     time.Time         `json:"created_at"`
	LastUpdatedAt time.Time         `json:"last_updated_at"`
	Count         int64             `json:"count,omitempty"`
}

type LogEntry struct {
	Time         time.Time         `json:"time"`
	Level        string            `json:"level"`
	Message      string            `json:"message"`
	ConnectionID string            `json:"connection_id,omitempty"`
	PID          uint32            `json:"pid,omitempty"`
	ExePath      string            `json:"exe_path,omitempty"`
	Action       config.RuleAction `json:"action,omitempty"`
	RuleID       string            `json:"rule_id,omitempty"`
	RuleName     string            `json:"rule_name,omitempty"`
	Host         string            `json:"host,omitempty"`
	Port         uint16            `json:"port,omitempty"`
}

type TrafficSample struct {
	Time      time.Time `json:"time"`
	UpBytes   int64     `json:"up_bytes"`
	DownBytes int64     `json:"down_bytes"`
}

type TrafficTotals struct {
	UpBytes   int64 `json:"up_bytes"`
	DownBytes int64 `json:"down_bytes"`
}

type RuleActivity struct {
	RuleID      string            `json:"rule_id,omitempty"`
	RuleName    string            `json:"rule_name,omitempty"`
	Action      config.RuleAction `json:"action"`
	Connections int64             `json:"connections"`
	UpBytes     int64             `json:"up_bytes"`
	DownBytes   int64             `json:"down_bytes"`
}

type Snapshot struct {
	Connections          []Connection    `json:"connections"`
	NewConnections       []Connection    `json:"new_connections"`
	Logs                 []LogEntry      `json:"logs"`
	Traffic              []TrafficSample `json:"traffic"`
	TrafficTotals        TrafficTotals   `json:"traffic_totals"`
	TrafficBucketSeconds int             `json:"traffic_bucket_seconds"`
	RuleStats            []RuleActivity  `json:"rule_stats"`
	RetentionMinutes     int             `json:"retention_minutes"`
	NewBaselineMinutes   int             `json:"new_baseline_minutes"`
	NewRecentMinutes     int             `json:"new_recent_minutes"`
}

type SnapshotOptions struct {
	IncludeLogs bool
}

type TrayView struct {
	Traffic []TrafficSample `json:"traffic"`
}

type Event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type Bus struct {
	mu               sync.RWMutex
	active           map[string]Connection
	trafficLive      map[int64]TrafficSample
	subs             map[int]chan []byte
	nextSubID        int
	activeDeletes    int
	trafficDeletes   int
	uiActiveUntil    time.Time
	uiWake           chan struct{}
	retentionWindow  time.Duration
	history          *history.Store
	lastActivePrune  time.Time
	lastTrafficPrune time.Time
}

const (
	uiVerboseWindow          = 90 * time.Second
	defaultRetention         = 7 * time.Minute
	maxRetention             = 24 * time.Hour
	newConnectionRecent      = time.Minute
	snapshotTrafficMaxPoints = 120
	trayKeepWindow           = 2 * time.Minute
	openingMaxAge            = 2 * time.Minute
	mapCompactDeletes        = 256
	pruneActiveEvery         = 15 * time.Second
	pruneTrafficEvery        = 15 * time.Second
)

func NewBus(historyPath string) (*Bus, error) {
	hist, err := history.Open(historyPath, defaultRetention)
	if err != nil {
		return nil, err
	}
	return &Bus{
		active:          map[string]Connection{},
		trafficLive:     map[int64]TrafficSample{},
		subs:            map[int]chan []byte{},
		uiWake:          make(chan struct{}, 1),
		retentionWindow: defaultRetention,
		history:         hist,
	}, nil
}

func (b *Bus) Close() error {
	if b.history != nil {
		return b.history.Close()
	}
	return nil
}

func normalizeRetentionWindow(d time.Duration) time.Duration {
	if d < time.Minute {
		return defaultRetention
	}
	if d > maxRetention {
		return maxRetention
	}
	return d
}

func (b *Bus) retentionWindowLocked() time.Duration {
	return normalizeRetentionWindow(b.retentionWindow)
}

func (b *Bus) SetRetentionWindow(d time.Duration) {
	d = normalizeRetentionWindow(d)
	b.mu.Lock()
	b.retentionWindow = d
	now := time.Now().UTC()
	b.pruneActiveLocked(now)
	b.pruneTrafficLiveLocked(now)
	b.mu.Unlock()
	if b.history != nil {
		b.history.SetRetentionWindow(d)
	}
}

func (b *Bus) MarkUIActive() {
	b.mu.Lock()
	b.uiActiveUntil = time.Now().UTC().Add(uiVerboseWindow)
	b.signalUIWakeLocked()
	b.mu.Unlock()
}

func (b *Bus) MarkUIInactive() {
	b.mu.Lock()
	b.uiActiveUntil = time.Time{}
	b.mu.Unlock()
}

func (b *Bus) DisableUI() {
	b.mu.Lock()
	b.uiActiveUntil = time.Time{}
	for id, ch := range b.subs {
		close(ch)
		delete(b.subs, id)
	}
	b.mu.Unlock()
}

func (b *Bus) UIActive() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.uiActiveLocked(time.Now().UTC())
}

func (b *Bus) uiActiveLocked(now time.Time) bool {
	return len(b.subs) > 0 || now.Before(b.uiActiveUntil)
}

func (b *Bus) UIWake() <-chan struct{} {
	b.mu.RLock()
	ch := b.uiWake
	b.mu.RUnlock()
	return ch
}

func (b *Bus) UpsertConnection(c Connection) {
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.LastUpdatedAt = now
	if c.Count <= 0 {
		c.Count = 1
	}
	state := strings.ToLower(strings.TrimSpace(c.State))
	persist := state == "closed" || state == "blocked" || state == "error"

	b.mu.Lock()
	if !persist {
		if old, ok := b.active[c.ID]; ok {
			if old.CreatedAt.Before(c.CreatedAt) {
				c.CreatedAt = old.CreatedAt
			}
			if c.BytesUp == 0 && old.BytesUp != 0 {
				c.BytesUp = old.BytesUp
			}
			if c.BytesDown == 0 && old.BytesDown != 0 {
				c.BytesDown = old.BytesDown
			}
		}
		b.active[c.ID] = c
		b.pruneActiveMaybeLocked(now)
	} else {
		if old, ok := b.active[c.ID]; ok {
			if old.CreatedAt.Before(c.CreatedAt) {
				c.CreatedAt = old.CreatedAt
			}
			if c.BytesUp == 0 && old.BytesUp != 0 {
				c.BytesUp = old.BytesUp
			}
			if c.BytesDown == 0 && old.BytesDown != 0 {
				c.BytesDown = old.BytesDown
			}
		}
		b.deleteActiveLocked(c.ID)
	}
	b.mu.Unlock()

	if persist && b.history != nil {
		b.history.RecordConnection(toHistoryConnection(c))
	}
}

func (b *Bus) DeleteConnection(id string) {
	b.mu.Lock()
	b.deleteActiveLocked(id)
	b.mu.Unlock()
}

func (b *Bus) AddLog(level, format string, args ...interface{}) {
	if !b.shouldCaptureLog(level) {
		return
	}
	b.publishLog(LogEntry{
		Time:    time.Now().UTC(),
		Level:   level,
		Message: fmt.Sprintf(format, args...),
	})
}

func (b *Bus) AddConnectionLog(level string, c Connection, format string, args ...interface{}) {
	if !b.shouldCaptureLog(level) {
		return
	}
	b.publishLog(LogEntry{
		Time:         time.Now().UTC(),
		Level:        level,
		Message:      fmt.Sprintf(format, args...),
		ConnectionID: c.ID,
		PID:          c.PID,
		ExePath:      c.ExePath,
		Action:       c.Action,
		RuleID:       c.RuleID,
		RuleName:     c.RuleName,
		Host:         hostForConnection(c),
		Port:         c.OriginalPort,
	})
}

func (b *Bus) publishLog(entry LogEntry) {
	if b.history != nil {
		b.history.RecordLog(toHistoryLog(entry))
	}
	payload := b.mustJSON(Event{Type: "log", Data: entry})
	b.mu.Lock()
	b.broadcastLocked(payload)
	b.mu.Unlock()
}

func (b *Bus) shouldCaptureLog(level string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "warn", "warning", "error":
		return true
	default:
		now := time.Now().UTC()
		return b.uiActiveLocked(now)
	}
}

func (b *Bus) AddTraffic(action config.RuleAction, upBytes, downBytes int64) {
	if action != config.ActionProxy && action != config.ActionChain {
		return
	}
	if upBytes == 0 && downBytes == 0 {
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	bucket := now.Unix()
	b.mu.Lock()
	sample := b.trafficLive[bucket]
	if sample.Time.IsZero() {
		sample.Time = now
	}
	sample.UpBytes += upBytes
	sample.DownBytes += downBytes
	b.trafficLive[bucket] = sample
	b.pruneTrafficLiveMaybeLocked(now)
	b.mu.Unlock()
	if b.history != nil {
		b.history.AddTraffic(now, upBytes, downBytes)
	}
}

func (b *Bus) AddRuleConnection(ruleID, ruleName string, action config.RuleAction) {
	if b.history != nil {
		b.history.AddRuleActivity(time.Now().UTC(), ruleID, ruleName, action, 1, 0, 0)
	}
}

func (b *Bus) AddRuleTraffic(ruleID, ruleName string, action config.RuleAction, upBytes, downBytes int64) {
	if b.history != nil {
		b.history.AddRuleActivity(time.Now().UTC(), ruleID, ruleName, action, 0, upBytes, downBytes)
	}
}

func (b *Bus) Snapshot() Snapshot {
	return b.SnapshotWithOptions(SnapshotOptions{IncludeLogs: true})
}

func (b *Bus) SnapshotWithOptions(options SnapshotOptions) Snapshot {
	b.mu.Lock()
	now := time.Now().UTC()
	b.pruneActiveMaybeLocked(now)
	b.pruneTrafficLiveMaybeLocked(now)
	active := make([]Connection, 0, len(b.active))
	for _, c := range b.active {
		active = append(active, c)
	}
	retention := b.retentionWindowLocked()
	b.mu.Unlock()

	trafficBucketSeconds := snapshotTrafficBucketSeconds(retention)
	newBaseline := newConnectionBaselineWindow(retention)
	newRecent := newConnectionRecentWindow(newBaseline)
	data, err := b.history.SnapshotWithOptions(retention, history.SnapshotOptions{
		IncludeLogs:          options.IncludeLogs,
		TrafficBucketSeconds: trafficBucketSeconds,
	})
	if err != nil {
		// fall back to only active connections; surface error via generic log path.
		return Snapshot{
			Connections:          sortConnections(active),
			TrafficBucketSeconds: trafficBucketSeconds,
			RetentionMinutes:     int(retention / time.Minute),
			NewBaselineMinutes:   int(newBaseline / time.Minute),
			NewRecentMinutes:     int(newRecent / time.Minute),
		}
	}
	conns := active
	for _, item := range data.Connections {
		conns = append(conns, fromHistoryConnection(item))
	}
	liveRecords := make([]history.ConnectionRecord, 0, len(active))
	for _, item := range active {
		liveRecords = append(liveRecords, toHistoryConnection(item))
	}
	var newConnections []Connection
	if items, err := b.history.NewConnections(history.NewConnectionOptions{
		Baseline: newBaseline,
		Recent:   newRecent,
		Limit:    512,
		Live:     liveRecords,
	}); err == nil {
		newConnections = make([]Connection, 0, len(items))
		for _, item := range items {
			newConnections = append(newConnections, fromHistoryConnection(item))
		}
	}
	var logs []LogEntry
	if options.IncludeLogs {
		logs = make([]LogEntry, 0, len(data.Logs))
		for _, item := range data.Logs {
			logs = append(logs, fromHistoryLog(item))
		}
	}
	traffic := make([]TrafficSample, 0, len(data.Traffic))
	for _, item := range data.Traffic {
		traffic = append(traffic, TrafficSample{Time: item.Time, UpBytes: item.UpBytes, DownBytes: item.DownBytes})
	}
	ruleStats := make([]RuleActivity, 0, len(data.RuleStats))
	for _, item := range data.RuleStats {
		ruleStats = append(ruleStats, RuleActivity(item))
	}
	return Snapshot{
		Connections:          sortConnections(conns),
		NewConnections:       sortConnections(newConnections),
		Logs:                 logs,
		Traffic:              traffic,
		TrafficTotals:        TrafficTotals(data.TrafficTotals),
		TrafficBucketSeconds: trafficBucketSeconds,
		RuleStats:            ruleStats,
		RetentionMinutes:     int(retention / time.Minute),
		NewBaselineMinutes:   int(newBaseline / time.Minute),
		NewRecentMinutes:     int(newRecent / time.Minute),
	}
}

func newConnectionBaselineWindow(retention time.Duration) time.Duration {
	return normalizeRetentionWindow(retention)
}

func newConnectionRecentWindow(baseline time.Duration) time.Duration {
	if baseline < time.Minute {
		return time.Minute
	}
	if baseline < newConnectionRecent {
		return baseline
	}
	return newConnectionRecent
}

func snapshotTrafficBucketSeconds(retention time.Duration) int {
	seconds := int((retention + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	bucketSeconds := (seconds + snapshotTrafficMaxPoints - 1) / snapshotTrafficMaxPoints
	if bucketSeconds < 1 {
		return 1
	}
	return bucketSeconds
}

func (b *Bus) TrayView(seconds int) TrayView {
	if seconds < 12 {
		seconds = 12
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now().UTC().Truncate(time.Second)
	out := make([]TrafficSample, 0, seconds)
	for i := seconds - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Second)
		s := b.trafficLive[t.Unix()]
		if s.Time.IsZero() {
			s.Time = t
		}
		out = append(out, s)
	}
	return TrayView{Traffic: out}
}

func (b *Bus) pruneTrafficLiveMaybeLocked(now time.Time) {
	if now.Sub(b.lastTrafficPrune) < pruneTrafficEvery {
		return
	}
	b.pruneTrafficLiveLocked(now)
}

func (b *Bus) pruneTrafficLiveLocked(now time.Time) {
	b.lastTrafficPrune = now
	cutoff := now.Add(-trayKeepWindow).Unix()
	for ts := range b.trafficLive {
		if ts < cutoff {
			delete(b.trafficLive, ts)
			b.trafficDeletes++
		}
	}
	b.compactTrafficLiveMaybeLocked()
}

func (b *Bus) pruneActiveMaybeLocked(now time.Time) {
	if now.Sub(b.lastActivePrune) < pruneActiveEvery {
		return
	}
	b.pruneActiveLocked(now)
}

func (b *Bus) pruneActiveLocked(now time.Time) {
	b.lastActivePrune = now
	for id, c := range b.active {
		if shouldExpireConnection(now, c, b.retentionWindowLocked()) {
			b.deleteActiveLocked(id)
		}
	}
}

func shouldExpireConnection(now time.Time, c Connection, keepFor time.Duration) bool {
	last := c.LastUpdatedAt
	if last.IsZero() {
		last = c.CreatedAt
	}
	if last.IsZero() {
		last = now
	}
	switch strings.ToLower(strings.TrimSpace(c.State)) {
	case "open":
		return false
	case "opening":
		return now.Sub(last) > openingMaxAge
	default:
		return now.Sub(last) > keepFor
	}
}

func (b *Bus) deleteActiveLocked(id string) {
	if _, ok := b.active[id]; !ok {
		return
	}
	delete(b.active, id)
	b.activeDeletes++
	b.compactActiveMaybeLocked()
}

func (b *Bus) compactActiveMaybeLocked() {
	if len(b.active) == 0 {
		if b.activeDeletes >= mapCompactDeletes {
			b.active = map[string]Connection{}
		}
		b.activeDeletes = 0
		return
	}
	if b.activeDeletes < mapCompactDeletes {
		return
	}
	next := make(map[string]Connection, len(b.active))
	for id, item := range b.active {
		next[id] = item
	}
	b.active = next
	b.activeDeletes = 0
}

func (b *Bus) compactTrafficLiveMaybeLocked() {
	if len(b.trafficLive) == 0 {
		if b.trafficDeletes >= mapCompactDeletes {
			b.trafficLive = map[int64]TrafficSample{}
		}
		b.trafficDeletes = 0
		return
	}
	if b.trafficDeletes < mapCompactDeletes {
		return
	}
	next := make(map[int64]TrafficSample, len(b.trafficLive))
	for ts, item := range b.trafficLive {
		next[ts] = item
	}
	b.trafficLive = next
	b.trafficDeletes = 0
}

func (b *Bus) Subscribe() (int, <-chan []byte, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextSubID
	b.nextSubID++
	ch := make(chan []byte, 64)
	b.subs[id] = ch
	b.uiActiveUntil = time.Now().UTC().Add(uiVerboseWindow)
	b.signalUIWakeLocked()
	cancel := func() {
		b.mu.Lock()
		if sub, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(sub)
		}
		b.mu.Unlock()
	}
	return id, ch, cancel
}

func (b *Bus) signalUIWakeLocked() {
	if b.uiWake == nil {
		return
	}
	select {
	case b.uiWake <- struct{}{}:
	default:
	}
}

func (b *Bus) mustJSON(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}

func (b *Bus) broadcastLocked(payload []byte) {
	for id, ch := range b.subs {
		select {
		case ch <- payload:
		default:
			close(ch)
			delete(b.subs, id)
		}
	}
}

func ConnID(pid uint32, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) string {
	return fmt.Sprintf("%d|%s|%d|%s|%d", pid, srcIP, srcPort, dstIP, dstPort)
}

func hostForConnection(c Connection) string {
	if strings.TrimSpace(c.Hostname) != "" {
		return c.Hostname
	}
	return c.OriginalIP
}

func sortConnections(items []Connection) []Connection {
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastUpdatedAt.Equal(items[j].LastUpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].LastUpdatedAt.After(items[j].LastUpdatedAt)
	})
	return items
}

func toHistoryConnection(c Connection) history.ConnectionRecord {
	return history.ConnectionRecord{
		ID:            c.ID,
		PID:           c.PID,
		ExePath:       c.ExePath,
		SourceIP:      c.SourceIP,
		SourcePort:    c.SourcePort,
		OriginalIP:    c.OriginalIP,
		OriginalPort:  c.OriginalPort,
		Hostname:      c.Hostname,
		RuleID:        c.RuleID,
		RuleName:      c.RuleName,
		Action:        c.Action,
		ProxyID:       c.ProxyID,
		ChainID:       c.ChainID,
		State:         c.State,
		BytesUp:       c.BytesUp,
		BytesDown:     c.BytesDown,
		CreatedAt:     c.CreatedAt,
		LastUpdatedAt: c.LastUpdatedAt,
		Count:         c.Count,
	}
}

func fromHistoryConnection(c history.ConnectionRecord) Connection {
	return Connection{
		ID:            c.ID,
		PID:           c.PID,
		ExePath:       c.ExePath,
		SourceIP:      c.SourceIP,
		SourcePort:    c.SourcePort,
		OriginalIP:    c.OriginalIP,
		OriginalPort:  c.OriginalPort,
		Hostname:      c.Hostname,
		RuleID:        c.RuleID,
		RuleName:      c.RuleName,
		Action:        c.Action,
		ProxyID:       c.ProxyID,
		ChainID:       c.ChainID,
		State:         c.State,
		BytesUp:       c.BytesUp,
		BytesDown:     c.BytesDown,
		CreatedAt:     c.CreatedAt,
		LastUpdatedAt: c.LastUpdatedAt,
		Count:         c.Count,
	}
}

func toHistoryLog(l LogEntry) history.LogRecord {
	return history.LogRecord{
		Time:         l.Time,
		Level:        l.Level,
		Message:      l.Message,
		ConnectionID: l.ConnectionID,
		PID:          l.PID,
		ExePath:      l.ExePath,
		Action:       l.Action,
		RuleID:       l.RuleID,
		RuleName:     l.RuleName,
		Host:         l.Host,
		Port:         l.Port,
	}
}

func fromHistoryLog(l history.LogRecord) LogEntry {
	return LogEntry{
		Time:         l.Time,
		Level:        l.Level,
		Message:      l.Message,
		ConnectionID: l.ConnectionID,
		PID:          l.PID,
		ExePath:      l.ExePath,
		Action:       l.Action,
		RuleID:       l.RuleID,
		RuleName:     l.RuleName,
		Host:         l.Host,
		Port:         l.Port,
	}
}
