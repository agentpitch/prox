package history

import (
	"bufio"
	"bytes"
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentpitch/prox/internal/config"
)

type Store struct {
	root string

	mu                 sync.Mutex
	flushMu            sync.Mutex
	pendingLogs        []LogRecord
	pendingConnections []ConnectionRecord
	pendingDropped     []DroppedRecord
	pendingTraffic     map[int64]TrafficSample
	pendingRule        map[string]rulePending
	retention          atomic.Int64
	droppedMaxBytes    atomic.Int64
	droppedSeq         atomic.Uint64
	droppedLimitDirty  atomic.Bool
	lastPrune          time.Time
	wake               chan struct{}
	retry              chan struct{}
	flushNow           chan struct{}
	stop               chan struct{}
	closeOnce          sync.Once
	closeErr           error
	lastError          string
	lastErrorAt        time.Time
	recoveredTailBytes int64
	skippedLines       atomic.Int64
	discardedPending   atomic.Int64
	wg                 sync.WaitGroup
}

type DiagnosticStats struct {
	PendingLogs           int       `json:"pending_logs"`
	PendingConnections    int       `json:"pending_connections"`
	PendingDropped        int       `json:"pending_dropped"`
	PendingTrafficBuckets int       `json:"pending_traffic_buckets"`
	PendingRuleBuckets    int       `json:"pending_rule_buckets"`
	RetentionSeconds      int64     `json:"retention_seconds"`
	DroppedMaxBytes       int64     `json:"dropped_max_bytes"`
	RecoveredTailBytes    int64     `json:"recovered_tail_bytes"`
	SkippedLines          int64     `json:"skipped_lines"`
	DiscardedPending      int64     `json:"discarded_pending"`
	LastError             string    `json:"last_error,omitempty"`
	LastErrorAt           time.Time `json:"last_error_at,omitempty"`
}

type rulePending struct {
	Ts   int64
	Item RuleActivity
}

type timedRuleActivity struct {
	Time time.Time `json:"time"`
	RuleActivity
}

type connectionAggregate struct {
	Item        ConnectionRecord
	BlockedOnly bool
	SawError    bool
}

type noveltyAggregate struct {
	Item        ConnectionRecord
	FirstSeen   time.Time
	BlockedOnly bool
	SawError    bool
	HasOpen     bool
}

type SnapshotOptions struct {
	IncludeLogs          bool
	TrafficBucketSeconds int
}

const (
	flushInterval               = 3 * time.Second
	flushRetryInterval          = 30 * time.Second
	pruneInterval               = time.Minute
	maxPendingLogs              = 8192
	maxPendingConnections       = 8192
	maxPendingDropped           = 1024
	maxPendingTrafficBuckets    = 2048
	maxPendingRuleBuckets       = 4096
	maxInitialConnectionQuery   = 2048
	connectionQueryPruneTrigger = maxInitialConnectionQuery * 2
	maxNewConnectionQuery       = 512
	newConnectionPruneTrigger   = maxNewConnectionQuery * 16
	maxInitialLogQuery          = 5000
	defaultDroppedQueryLimit    = 100
	maxDroppedQueryLimit        = 500
	segmentLayout               = "2006010215"
)

func Open(path string, retention time.Duration) (*Store, error) {
	root := segmentRoot(path)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create history dir: %w", err)
	}
	s := &Store{
		root:           root,
		pendingTraffic: map[int64]TrafficSample{},
		pendingRule:    map[string]rulePending{},
		wake:           make(chan struct{}, 1),
		retry:          make(chan struct{}, 1),
		flushNow:       make(chan struct{}, 1),
		stop:           make(chan struct{}),
	}
	recovered, err := recoverJSONLTails(root)
	if err != nil {
		return nil, err
	}
	s.recoveredTailBytes = recovered
	s.SetRetentionWindow(retention)
	s.SetDroppedLogMaxBytes(config.DefaultDroppedLogMaxBytes)
	s.wg.Add(1)
	go s.loop()
	return s, nil
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

func (s *Store) SetRetentionWindow(d time.Duration) {
	if d < time.Minute {
		d = 7 * time.Minute
	}
	s.retention.Store(int64(d))
	s.wakeFlush()
}

func (s *Store) SetDroppedLogMaxBytes(n int64) {
	n = normalizeDroppedLogMaxBytes(n)
	old := s.droppedMaxBytes.Swap(n)
	if old != n {
		s.droppedLimitDirty.Store(true)
		s.wakeFlush()
	}
}

func normalizeDroppedLogMaxBytes(n int64) int64 {
	if n <= 0 {
		return config.DefaultDroppedLogMaxBytes
	}
	if n < config.MinDroppedLogMaxBytes {
		return config.MinDroppedLogMaxBytes
	}
	if n > config.MaxDroppedLogMaxBytes {
		return config.MaxDroppedLogMaxBytes
	}
	return n
}

func (s *Store) DiagnosticStats() DiagnosticStats {
	if s == nil {
		return DiagnosticStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return DiagnosticStats{
		PendingLogs:           len(s.pendingLogs),
		PendingConnections:    len(s.pendingConnections),
		PendingDropped:        len(s.pendingDropped),
		PendingTrafficBuckets: len(s.pendingTraffic),
		PendingRuleBuckets:    len(s.pendingRule),
		RetentionSeconds:      int64(time.Duration(s.retention.Load()) / time.Second),
		DroppedMaxBytes:       s.droppedMaxBytes.Load(),
		RecoveredTailBytes:    s.recoveredTailBytes,
		SkippedLines:          s.skippedLines.Load(),
		DiscardedPending:      s.discardedPending.Load(),
		LastError:             s.lastError,
		LastErrorAt:           s.lastErrorAt,
	}
}

func (s *Store) RecordLog(entry LogRecord) {
	s.mu.Lock()
	if len(s.pendingLogs) >= maxPendingLogs {
		s.discardedPending.Add(1)
		s.mu.Unlock()
		return
	}
	wasEmpty := s.pendingEmptyLocked()
	s.pendingLogs = append(s.pendingLogs, entry)
	count := len(s.pendingLogs)
	s.mu.Unlock()
	if wasEmpty {
		s.wakeFlush()
	}
	if count == 64 {
		s.wakeFlushNow()
	}
}

func (s *Store) RecordConnection(entry ConnectionRecord) {
	s.mu.Lock()
	if len(s.pendingConnections) >= maxPendingConnections {
		s.discardedPending.Add(1)
		s.mu.Unlock()
		return
	}
	wasEmpty := s.pendingEmptyLocked()
	s.pendingConnections = append(s.pendingConnections, entry)
	count := len(s.pendingConnections)
	s.mu.Unlock()
	if wasEmpty {
		s.wakeFlush()
	}
	if count == 64 {
		s.wakeFlushNow()
	}
}

func (s *Store) RecordDroppedConnection(entry ConnectionRecord) {
	ts := entry.LastUpdatedAt.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = ts
	}
	entry.LastUpdatedAt = ts
	if entry.Count <= 0 {
		entry.Count = 1
	}
	item := DroppedRecord{
		DropID:     fmt.Sprintf("%016x-%08x", ts.UnixNano(), s.droppedSeq.Add(1)),
		DroppedAt:  ts,
		Connection: entry,
	}
	s.mu.Lock()
	if len(s.pendingDropped) >= maxPendingDropped {
		s.discardedPending.Add(1)
		s.mu.Unlock()
		return
	}
	wasEmpty := s.pendingEmptyLocked()
	s.pendingDropped = append(s.pendingDropped, item)
	count := len(s.pendingDropped)
	s.mu.Unlock()
	if wasEmpty {
		s.wakeFlush()
	}
	if count == 16 {
		s.wakeFlushNow()
	}
}

func (s *Store) AddTraffic(ts time.Time, upBytes, downBytes int64) {
	if upBytes == 0 && downBytes == 0 {
		return
	}
	bucket := ts.UTC().Truncate(time.Second)
	key := bucket.Unix()
	s.mu.Lock()
	wasEmpty := s.pendingEmptyLocked()
	item, exists := s.pendingTraffic[key]
	if !exists && len(s.pendingTraffic) >= maxPendingTrafficBuckets {
		s.discardedPending.Add(1)
		s.mu.Unlock()
		return
	}
	if item.Time.IsZero() {
		item.Time = bucket
	}
	item.UpBytes += upBytes
	item.DownBytes += downBytes
	s.pendingTraffic[key] = item
	s.mu.Unlock()
	if wasEmpty {
		s.wakeFlush()
	}
}

func (s *Store) AddRuleActivity(ts time.Time, ruleID, ruleName string, action config.RuleAction, conns, upBytes, downBytes int64) {
	if strings.TrimSpace(ruleID) == "" && strings.TrimSpace(ruleName) == "" {
		return
	}
	if conns == 0 && upBytes == 0 && downBytes == 0 {
		return
	}
	bucket := ts.UTC().Truncate(time.Second)
	key := fmt.Sprintf("%d\x1f%s\x1f%s\x1f%s", bucket.Unix(), strings.ToLower(strings.TrimSpace(ruleID)), strings.ToLower(strings.TrimSpace(ruleName)), strings.ToLower(strings.TrimSpace(string(action))))
	s.mu.Lock()
	wasEmpty := s.pendingEmptyLocked()
	item, exists := s.pendingRule[key]
	if !exists && len(s.pendingRule) >= maxPendingRuleBuckets {
		s.discardedPending.Add(1)
		s.mu.Unlock()
		return
	}
	item.Ts = bucket.Unix()
	if item.Item.RuleID == "" {
		item.Item.RuleID = ruleID
		item.Item.RuleName = ruleName
		item.Item.Action = action
	}
	item.Item.Connections += conns
	item.Item.UpBytes += upBytes
	item.Item.DownBytes += downBytes
	s.pendingRule[key] = item
	s.mu.Unlock()
	if wasEmpty {
		s.wakeFlush()
	}
}

func (s *Store) Snapshot(retention time.Duration) (SnapshotData, error) {
	return s.SnapshotWithOptions(retention, SnapshotOptions{IncludeLogs: true, TrafficBucketSeconds: 1})
}

func (s *Store) SnapshotWithOptions(retention time.Duration, options SnapshotOptions) (SnapshotData, error) {
	if retention < time.Minute {
		retention = time.Duration(s.retention.Load())
	}
	if err := s.Flush(); err != nil {
		return SnapshotData{}, err
	}
	cutoff := time.Now().UTC().Add(-retention)
	out := SnapshotData{}
	var err error
	if out.Connections, err = s.queryConnections(cutoff); err != nil {
		return SnapshotData{}, err
	}
	if options.IncludeLogs {
		if out.Logs, err = s.queryLogs(cutoff); err != nil {
			return SnapshotData{}, err
		}
	}
	if out.Traffic, out.TrafficTotals, err = s.queryTraffic(cutoff, options.TrafficBucketSeconds); err != nil {
		return SnapshotData{}, err
	}
	if out.RuleStats, err = s.queryRuleStats(cutoff); err != nil {
		return SnapshotData{}, err
	}
	return out, nil
}

func (s *Store) NewConnections(options NewConnectionOptions) ([]ConnectionRecord, error) {
	baseline := options.Baseline
	if baseline < time.Minute {
		baseline = time.Duration(s.retention.Load())
	}
	recent := options.Recent
	if recent < time.Minute {
		recent = time.Minute
	}
	if baseline <= recent {
		return nil, nil
	}
	limit := options.Limit
	if limit <= 0 || limit > maxNewConnectionQuery {
		limit = maxNewConnectionQuery
	}
	if err := s.Flush(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	cutoff := now.Add(-baseline)
	recentCutoff := now.Add(-recent)
	candidates := make(map[string]noveltyAggregate, min(maxNewConnectionQuery, limit*2))
	recordTimes := func(item ConnectionRecord) (time.Time, time.Time) {
		ts := item.LastUpdatedAt.UTC()
		if ts.IsZero() {
			ts = now
		}
		firstSeen := item.CreatedAt.UTC()
		if firstSeen.IsZero() {
			firstSeen = ts
		}
		return firstSeen, ts
	}
	collectRecent := func(item ConnectionRecord) {
		firstSeen, ts := recordTimes(item)
		if ts.Before(cutoff) || ts.Before(recentCutoff) || firstSeen.Before(recentCutoff) {
			return
		}
		key := connectionNoveltyKey(item)
		if key == "" {
			return
		}
		mergeNoveltyAggregate(candidates, key, item, ts)
		if len(candidates) > newConnectionPruneTrigger {
			pruneNoveltyAggregates(candidates, newConnectionPruneTrigger/2)
		}
	}

	recentFiles, err := s.segmentFiles("connections", recentCutoff)
	if err != nil {
		return nil, err
	}
	for _, file := range recentFiles {
		if err := readSegmentFile(file, collectRecent, s.noteSkippedLine); err != nil {
			return nil, fmt.Errorf("query new connections: %w", err)
		}
	}
	for _, item := range options.Live {
		collectRecent(item)
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	baselineFiles, err := s.segmentFiles("connections", cutoff)
	if err != nil {
		return nil, err
	}
	markOld := func(item ConnectionRecord) {
		firstSeen, ts := recordTimes(item)
		if ts.Before(cutoff) || (!ts.Before(recentCutoff) && !firstSeen.Before(recentCutoff)) {
			return
		}
		key := connectionNoveltyKey(item)
		if key == "" {
			return
		}
		delete(candidates, key)
	}
	for _, file := range baselineFiles {
		if err := readSegmentFile(file, markOld, s.noteSkippedLine); err != nil {
			return nil, fmt.Errorf("query new connections baseline: %w", err)
		}
		if len(candidates) == 0 {
			return nil, nil
		}
	}

	out := make([]ConnectionRecord, 0, min(len(candidates), limit))
	for _, item := range candidates {
		out = append(out, item.Item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastUpdatedAt.Equal(out[j].LastUpdatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].LastUpdatedAt.After(out[j].LastUpdatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) DroppedConnections(query DroppedQuery) (DroppedResult, error) {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	if err := s.flushLocked(); err != nil {
		return DroppedResult{}, err
	}
	if err := s.enforceDroppedLimit(); err != nil {
		return DroppedResult{}, err
	}
	limit := normalizeDroppedQueryLimit(query.Limit)
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}
	tokens := droppedSearchTokens(query.Search)
	items := make([]DroppedRecord, 0, limit)
	total := 0
	fileBytes, err := scanLinesReverse(s.droppedPath(), func(line []byte) {
		var item DroppedRecord
		if err := json.Unmarshal(bytes.TrimSpace(line), &item); err != nil {
			s.noteSkippedLine()
			return
		}
		normalizeDroppedRecord(&item)
		if item.DropID == "" || !droppedMatchesSearch(item, tokens) {
			return
		}
		if total >= offset && len(items) < limit {
			items = append(items, item)
		}
		total++
	})
	if err != nil {
		return DroppedResult{}, err
	}
	if offset > total {
		offset = total
	}
	return DroppedResult{
		Items:     items,
		Total:     total,
		Offset:    offset,
		Limit:     limit,
		MaxBytes:  normalizeDroppedLogMaxBytes(s.droppedMaxBytes.Load()),
		FileBytes: fileBytes,
	}, nil
}

func normalizeDroppedQueryLimit(limit int) int {
	if limit <= 0 {
		return defaultDroppedQueryLimit
	}
	if limit > maxDroppedQueryLimit {
		return maxDroppedQueryLimit
	}
	return limit
}

func (s *Store) DeleteDroppedConnections(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	if err := s.flushLocked(); err != nil {
		return err
	}
	dropIDs := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			dropIDs[id] = struct{}{}
		}
	}
	if len(dropIDs) == 0 {
		return nil
	}
	if err := s.rewriteDroppedFiltered(func(item DroppedRecord) bool {
		_, remove := dropIDs[item.DropID]
		return !remove
	}); err != nil {
		return err
	}
	return s.enforceDroppedLimit()
}

func (s *Store) Flush() error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	return s.flushLocked()
}

type flushBatch struct {
	logs       []LogRecord
	conns      []ConnectionRecord
	dropped    []DroppedRecord
	traffic    map[int64]TrafficSample
	rules      map[string]rulePending
	limitDirty bool
}

func (s *Store) flushLocked() error {
	s.mu.Lock()
	batch := flushBatch{
		logs:       s.pendingLogs,
		conns:      s.pendingConnections,
		dropped:    s.pendingDropped,
		traffic:    s.pendingTraffic,
		rules:      s.pendingRule,
		limitDirty: s.droppedLimitDirty.Swap(false),
	}
	shouldPrune := time.Since(s.lastPrune) >= pruneInterval
	if batch.empty() && !shouldPrune {
		s.mu.Unlock()
		return nil
	}
	s.pendingLogs = nil
	s.pendingConnections = nil
	s.pendingDropped = nil
	s.pendingTraffic = map[int64]TrafficSample{}
	s.pendingRule = map[string]rulePending{}
	s.mu.Unlock()

	if err := s.appendLogs(batch.logs); err != nil {
		return s.failFlush(batch, err)
	}
	batch.logs = nil
	if err := s.appendConnections(batch.conns); err != nil {
		return s.failFlush(batch, err)
	}
	batch.conns = nil
	hadDropped := len(batch.dropped) > 0
	if err := s.appendDropped(batch.dropped); err != nil {
		return s.failFlush(batch, err)
	}
	batch.dropped = nil
	if hadDropped || batch.limitDirty {
		if err := s.enforceDroppedLimit(); err != nil {
			s.droppedLimitDirty.Store(true)
			batch.limitDirty = false
			return s.failFlush(batch, err)
		}
	}
	batch.limitDirty = false
	if err := s.appendTraffic(batch.traffic); err != nil {
		return s.failFlush(batch, err)
	}
	batch.traffic = nil
	if err := s.appendRules(batch.rules); err != nil {
		return s.failFlush(batch, err)
	}
	batch.rules = nil
	if shouldPrune {
		if err := s.pruneSegments(time.Now().UTC().Add(-time.Duration(s.retention.Load()))); err != nil {
			s.setLastError(err)
			s.wakeRetry()
			return err
		}
		s.mu.Lock()
		s.lastPrune = time.Now().UTC()
		s.mu.Unlock()
	}
	s.clearLastError()
	return nil
}

func (s *Store) loop() {
	defer s.wg.Done()
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var timerC <-chan time.Time
	var timerDue time.Time
	armTimer := func(delay time.Duration) {
		due := time.Now().Add(delay)
		if timerC != nil {
			if !due.Before(timerDue) {
				return
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		timer.Reset(delay)
		timerC = timer.C
		timerDue = due
	}
	stopTimer := func() {
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
		timerDue = time.Time{}
	}
	flush := func() {
		if err := s.Flush(); err != nil {
			armTimer(flushRetryInterval)
			return
		}
		if s.hasPending() {
			armTimer(flushInterval)
		}
	}
	for {
		select {
		case <-s.stop:
			stopTimer()
			err := s.Flush()
			s.mu.Lock()
			s.closeErr = err
			s.mu.Unlock()
			return
		case <-s.wake:
			armTimer(flushInterval)
		case <-s.retry:
			armTimer(flushRetryInterval)
		case <-s.flushNow:
			stopTimer()
			flush()
		case <-timerC:
			timerC = nil
			timerDue = time.Time{}
			flush()
		}
	}
}

func (s *Store) wakeFlush() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Store) wakeFlushNow() {
	select {
	case s.flushNow <- struct{}{}:
	default:
	}
}

func (s *Store) wakeRetry() {
	select {
	case s.retry <- struct{}{}:
	default:
	}
}

func (b flushBatch) empty() bool {
	return len(b.logs) == 0 && len(b.conns) == 0 && len(b.dropped) == 0 &&
		len(b.traffic) == 0 && len(b.rules) == 0 && !b.limitDirty
}

func (s *Store) pendingEmptyLocked() bool {
	return len(s.pendingLogs) == 0 && len(s.pendingConnections) == 0 &&
		len(s.pendingDropped) == 0 && len(s.pendingTraffic) == 0 &&
		len(s.pendingRule) == 0 && !s.droppedLimitDirty.Load()
}

func (s *Store) hasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.pendingEmptyLocked()
}

func (s *Store) failFlush(batch flushBatch, err error) error {
	s.mu.Lock()
	if len(batch.logs) > 0 {
		var discarded int
		s.pendingLogs, discarded = prependBounded(batch.logs, s.pendingLogs, maxPendingLogs)
		s.discardedPending.Add(int64(discarded))
	}
	if len(batch.conns) > 0 {
		var discarded int
		s.pendingConnections, discarded = prependBounded(batch.conns, s.pendingConnections, maxPendingConnections)
		s.discardedPending.Add(int64(discarded))
	}
	if len(batch.dropped) > 0 {
		var discarded int
		s.pendingDropped, discarded = prependBounded(batch.dropped, s.pendingDropped, maxPendingDropped)
		s.discardedPending.Add(int64(discarded))
	}
	for key, item := range batch.traffic {
		current, exists := s.pendingTraffic[key]
		if !exists && len(s.pendingTraffic) >= maxPendingTrafficBuckets {
			s.discardedPending.Add(1)
			continue
		}
		if current.Time.IsZero() {
			current.Time = item.Time
		}
		current.UpBytes += item.UpBytes
		current.DownBytes += item.DownBytes
		s.pendingTraffic[key] = current
	}
	for key, item := range batch.rules {
		current, exists := s.pendingRule[key]
		if !exists && len(s.pendingRule) >= maxPendingRuleBuckets {
			s.discardedPending.Add(1)
			continue
		}
		if current.Ts == 0 {
			current.Ts = item.Ts
		}
		if current.Item.RuleID == "" {
			current.Item.RuleID = item.Item.RuleID
			current.Item.RuleName = item.Item.RuleName
			current.Item.Action = item.Item.Action
		}
		current.Item.Connections += item.Item.Connections
		current.Item.UpBytes += item.Item.UpBytes
		current.Item.DownBytes += item.Item.DownBytes
		s.pendingRule[key] = current
	}
	if batch.limitDirty {
		s.droppedLimitDirty.Store(true)
	}
	s.lastError = err.Error()
	s.lastErrorAt = time.Now().UTC()
	s.mu.Unlock()
	s.wakeRetry()
	return err
}

func prependBounded[T any](older, newer []T, limit int) ([]T, int) {
	if limit <= 0 {
		return nil, len(older) + len(newer)
	}
	if len(older) >= limit {
		return older[:limit], len(older) - limit + len(newer)
	}
	keepNewer := min(len(newer), limit-len(older))
	out := append(older, newer[:keepNewer]...)
	return out, len(newer) - keepNewer
}

func (s *Store) setLastError(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.lastError = err.Error()
	s.lastErrorAt = time.Now().UTC()
	s.mu.Unlock()
}

func (s *Store) clearLastError() {
	s.mu.Lock()
	s.lastError = ""
	s.lastErrorAt = time.Time{}
	s.mu.Unlock()
}

func (s *Store) appendLogs(items []LogRecord) error {
	if len(items) == 0 {
		return nil
	}
	buffers, err := marshalBySegment("logs", len(items), func(write func(time.Time, any) error) error {
		for _, item := range items {
			if err := write(item.Time.UTC(), item); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.flushSegmentBuffers(buffers)
}

func (s *Store) appendConnections(items []ConnectionRecord) error {
	if len(items) == 0 {
		return nil
	}
	buffers, err := marshalBySegment("connections", len(items), func(write func(time.Time, any) error) error {
		for _, item := range items {
			ts := item.LastUpdatedAt.UTC()
			if ts.IsZero() {
				ts = time.Now().UTC()
			}
			if err := write(ts, item); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.flushSegmentBuffers(buffers)
}

func (s *Store) appendDropped(items []DroppedRecord) error {
	if len(items) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, item := range items {
		data, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("marshal dropped log: %w", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}
	return appendFileBuffersTransactional(map[string]*bytes.Buffer{s.droppedPath(): &buf})
}

func (s *Store) enforceDroppedLimit() error {
	maxBytes := normalizeDroppedLogMaxBytes(s.droppedMaxBytes.Load())
	path := s.droppedPath()
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat dropped log: %w", err)
	}
	if info.Size() <= maxBytes {
		return nil
	}
	start, err := nextLineOffset(path, info.Size()-maxBytes)
	if err != nil {
		return err
	}
	return rewriteFileTail(path, start)
}

func normalizeDroppedRecord(item *DroppedRecord) {
	if item == nil {
		return
	}
	if item.DroppedAt.IsZero() {
		item.DroppedAt = item.Connection.LastUpdatedAt
	}
}

func (s *Store) rewriteDroppedFiltered(keep func(DroppedRecord) bool) error {
	path := s.droppedPath()
	src, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open dropped log: %w", err)
	}
	defer src.Close()
	tmp := path + ".tmp"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open dropped log tmp: %w", err)
	}
	bw := bufio.NewWriterSize(dst, 64*1024)
	changed := false
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), 2<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			changed = true
			continue
		}
		var item DroppedRecord
		if err := json.Unmarshal(line, &item); err != nil {
			s.noteSkippedLine()
			changed = true
			continue
		}
		normalizeDroppedRecord(&item)
		if keep != nil && !keep(item) {
			changed = true
			continue
		}
		if _, err := bw.Write(line); err != nil {
			_ = dst.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("write dropped log tmp: %w", err)
		}
		if err := bw.WriteByte('\n'); err != nil {
			_ = dst.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("write dropped log tmp newline: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("read dropped log: %w", err)
	}
	if err := bw.Flush(); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("flush dropped log tmp: %w", err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close dropped log tmp: %w", err)
	}
	if err := src.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close dropped log: %w", err)
	}
	if !changed {
		_ = os.Remove(tmp)
		return nil
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace dropped log: %w", err)
	}
	return nil
}

func scanLinesReverse(path string, fn func([]byte)) (int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open dropped log: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat dropped log: %w", err)
	}
	const (
		chunkSize    = 64 * 1024
		maxLineBytes = 2 << 20
	)
	buf := make([]byte, chunkSize)
	var carry []byte
	droppingOversized := false
	pos := info.Size()
	process := func(line []byte) {
		line = bytes.TrimSpace(line)
		if len(line) > 0 && fn != nil {
			fn(line)
		}
	}
	for pos > 0 {
		start := pos - int64(len(buf))
		if start < 0 {
			start = 0
		}
		n, readErr := f.ReadAt(buf[:pos-start], start)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return info.Size(), fmt.Errorf("read dropped log backwards: %w", readErr)
		}
		chunk := buf[:n]
		if droppingOversized {
			idx := bytes.LastIndexByte(chunk, '\n')
			if idx < 0 {
				pos = start
				continue
			}
			droppingOversized = false
			chunk = chunk[:idx]
		}
		data := make([]byte, 0, len(chunk)+len(carry))
		data = append(data, chunk...)
		data = append(data, carry...)
		end := len(data)
		for {
			idx := bytes.LastIndexByte(data[:end], '\n')
			if idx < 0 {
				break
			}
			process(data[idx+1 : end])
			end = idx
		}
		carry = append(carry[:0], data[:end]...)
		if len(carry) > maxLineBytes {
			carry = nil
			droppingOversized = true
		}
		pos = start
	}
	if !droppingOversized {
		process(carry)
	}
	return info.Size(), nil
}

func nextLineOffset(path string, offset int64) (int64, error) {
	if offset <= 0 {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open dropped log for compaction: %w", err)
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	pos := offset
	for {
		n, readErr := f.ReadAt(buf, pos)
		if idx := bytes.IndexByte(buf[:n], '\n'); idx >= 0 {
			return pos + int64(idx) + 1, nil
		}
		pos += int64(n)
		if errors.Is(readErr, io.EOF) {
			return pos, nil
		}
		if readErr != nil {
			return 0, fmt.Errorf("scan dropped log compaction boundary: %w", readErr)
		}
	}
}

func rewriteFileTail(path string, start int64) error {
	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open dropped log for compaction: %w", err)
	}
	defer src.Close()
	if _, err := src.Seek(start, io.SeekStart); err != nil {
		return fmt.Errorf("seek dropped log for compaction: %w", err)
	}
	tmp := path + ".tmp"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open dropped log tmp: %w", err)
	}
	buf := make([]byte, 64*1024)
	_, copyErr := io.CopyBuffer(dst, src, buf)
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("compact dropped log: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close compacted dropped log: %w", closeErr)
	}
	if err := src.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close dropped log after compaction: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace dropped log: %w", err)
	}
	return nil
}

func (s *Store) appendTraffic(items map[int64]TrafficSample) error {
	if len(items) == 0 {
		return nil
	}
	keys := make([]int64, 0, len(items))
	for ts := range items {
		keys = append(keys, ts)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	buffers, err := marshalBySegment("traffic", len(keys), func(write func(time.Time, any) error) error {
		for _, ts := range keys {
			item := items[ts]
			if err := write(item.Time.UTC(), item); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.flushSegmentBuffers(buffers)
}

func (s *Store) appendRules(items map[string]rulePending) error {
	if len(items) == 0 {
		return nil
	}
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	buffers, err := marshalBySegment("rules", len(keys), func(write func(time.Time, any) error) error {
		for _, key := range keys {
			item := items[key]
			record := timedRuleActivity{Time: time.Unix(item.Ts, 0).UTC(), RuleActivity: item.Item}
			if err := write(record.Time, record); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.flushSegmentBuffers(buffers)
}

func marshalBySegment(prefix string, sizeHint int, emit func(write func(time.Time, any) error) error) (map[string]*bytes.Buffer, error) {
	buffers := make(map[string]*bytes.Buffer, max(1, sizeHint/16))
	write := func(ts time.Time, item any) error {
		name := segmentFileName(prefix, ts.UTC())
		buf := buffers[name]
		if buf == nil {
			buf = &bytes.Buffer{}
			buffers[name] = buf
		}
		data, err := json.Marshal(item)
		if err != nil {
			return err
		}
		buf.Write(data)
		buf.WriteByte('\n')
		return nil
	}
	if err := emit(write); err != nil {
		return nil, err
	}
	return buffers, nil
}

func (s *Store) flushSegmentBuffers(buffers map[string]*bytes.Buffer) error {
	if len(buffers) == 0 {
		return nil
	}
	paths := make(map[string]*bytes.Buffer, len(buffers))
	for name, buf := range buffers {
		paths[filepath.Join(s.root, name)] = buf
	}
	if err := appendFileBuffersTransactional(paths); err != nil {
		return fmt.Errorf("append history segments: %w", err)
	}
	return nil
}

type appendedFile struct {
	path    string
	size    int64
	existed bool
}

func appendFileBuffersTransactional(buffers map[string]*bytes.Buffer) error {
	paths := make([]string, 0, len(buffers))
	for path := range buffers {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	touched := make([]appendedFile, 0, len(paths))
	rollback := func() {
		for i := len(touched) - 1; i >= 0; i-- {
			item := touched[i]
			if !item.existed {
				_ = os.Remove(item.path)
				continue
			}
			_ = os.Truncate(item.path, item.size)
		}
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		existed := err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			rollback()
			return fmt.Errorf("stat %s: %w", filepath.Base(path), err)
		}
		var size int64
		if existed {
			size = info.Size()
		}
		touched = append(touched, appendedFile{path: path, size: size, existed: existed})
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			rollback()
			return fmt.Errorf("open %s: %w", filepath.Base(path), err)
		}
		data := buffers[path].Bytes()
		n, writeErr := f.Write(data)
		if writeErr == nil && n != len(data) {
			writeErr = io.ErrShortWrite
		}
		closeErr := f.Close()
		if writeErr != nil {
			rollback()
			return fmt.Errorf("write %s: %w", filepath.Base(path), writeErr)
		}
		if closeErr != nil {
			rollback()
			return fmt.Errorf("close %s: %w", filepath.Base(path), closeErr)
		}
	}
	return nil
}

func (s *Store) pruneSegments(cutoff time.Time) error {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return fmt.Errorf("list history segments: %w", err)
	}
	cutoff = cutoff.UTC()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		start, ok := parseSegmentTime(entry.Name())
		if !ok {
			continue
		}
		if !start.Add(time.Hour).After(cutoff) {
			if err := os.Remove(filepath.Join(s.root, entry.Name())); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("prune history segment %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}

func (s *Store) queryConnections(cutoff time.Time) ([]ConnectionRecord, error) {
	files, err := s.segmentFiles("connections", cutoff)
	if err != nil {
		return nil, err
	}
	agg := make(map[string]connectionAggregate, maxInitialConnectionQuery)
	for _, file := range files {
		if err := readSegmentFile(file, func(item ConnectionRecord) {
			if item.LastUpdatedAt.UTC().Before(cutoff) {
				return
			}
			key := connectionAggregateKey(item)
			state := strings.ToLower(strings.TrimSpace(item.State))
			count := item.Count
			if count <= 0 {
				count = 1
			}
			current, ok := agg[key]
			if !ok {
				if item.CreatedAt.IsZero() {
					item.CreatedAt = item.LastUpdatedAt
				}
				item.Count = count
				current = connectionAggregate{
					Item:        item,
					BlockedOnly: state == "blocked",
					SawError:    state == "error",
				}
			} else {
				if item.CreatedAt.IsZero() {
					item.CreatedAt = item.LastUpdatedAt
				}
				if current.Item.CreatedAt.IsZero() || (!item.CreatedAt.IsZero() && item.CreatedAt.Before(current.Item.CreatedAt)) {
					current.Item.CreatedAt = item.CreatedAt
				}
				if item.LastUpdatedAt.After(current.Item.LastUpdatedAt) {
					current.Item.ID = item.ID
					current.Item.SourceIP = item.SourceIP
					current.Item.SourcePort = item.SourcePort
					current.Item.LastUpdatedAt = item.LastUpdatedAt
				}
				current.Item.BytesUp += item.BytesUp
				current.Item.BytesDown += item.BytesDown
				current.Item.Count += count
				current.BlockedOnly = current.BlockedOnly && state == "blocked"
				current.SawError = current.SawError || state == "error"
			}
			switch {
			case current.SawError:
				current.Item.State = "error"
			case current.BlockedOnly:
				current.Item.State = "blocked"
			default:
				current.Item.State = "closed"
			}
			agg[key] = current
			if len(agg) > connectionQueryPruneTrigger {
				pruneConnectionAggregates(agg, maxInitialConnectionQuery)
			}
		}, s.noteSkippedLine); err != nil {
			return nil, fmt.Errorf("query connections: %w", err)
		}
	}
	pruneConnectionAggregates(agg, maxInitialConnectionQuery)
	out := make([]ConnectionRecord, 0, len(agg))
	for _, item := range agg {
		out = append(out, item.Item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastUpdatedAt.Equal(out[j].LastUpdatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].LastUpdatedAt.After(out[j].LastUpdatedAt)
	})
	return out, nil
}

func pruneConnectionAggregates(agg map[string]connectionAggregate, limit int) {
	if limit <= 0 || len(agg) <= limit {
		return
	}
	type rankedConnection struct {
		Key           string
		LastUpdatedAt time.Time
		CreatedAt     time.Time
	}
	ranked := make([]rankedConnection, 0, len(agg))
	for key, item := range agg {
		ranked = append(ranked, rankedConnection{
			Key:           key,
			LastUpdatedAt: item.Item.LastUpdatedAt,
			CreatedAt:     item.Item.CreatedAt,
		})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].LastUpdatedAt.Equal(ranked[j].LastUpdatedAt) {
			return ranked[i].CreatedAt.After(ranked[j].CreatedAt)
		}
		return ranked[i].LastUpdatedAt.After(ranked[j].LastUpdatedAt)
	})
	for _, item := range ranked[limit:] {
		delete(agg, item.Key)
	}
}

func mergeNoveltyAggregate(agg map[string]noveltyAggregate, key string, item ConnectionRecord, ts time.Time) {
	firstSeen := item.CreatedAt.UTC()
	if firstSeen.IsZero() {
		firstSeen = ts
	}
	state := strings.ToLower(strings.TrimSpace(item.State))
	count := item.Count
	if count <= 0 {
		count = 1
	}
	item.CreatedAt = firstSeen
	item.LastUpdatedAt = ts
	item.Count = count
	current, ok := agg[key]
	if !ok {
		agg[key] = noveltyAggregate{
			Item:        item,
			FirstSeen:   firstSeen,
			BlockedOnly: state == "blocked",
			SawError:    state == "error",
			HasOpen:     state == "open" || state == "opening",
		}
		return
	}
	totalUp := current.Item.BytesUp + item.BytesUp
	totalDown := current.Item.BytesDown + item.BytesDown
	totalCount := current.Item.Count + count
	if firstSeen.Before(current.FirstSeen) {
		current.FirstSeen = firstSeen
	}
	if ts.After(current.Item.LastUpdatedAt) {
		current.Item = item
	}
	current.Item.CreatedAt = current.FirstSeen
	current.Item.BytesUp = totalUp
	current.Item.BytesDown = totalDown
	current.Item.Count = totalCount
	current.BlockedOnly = current.BlockedOnly && state == "blocked"
	current.SawError = current.SawError || state == "error"
	current.HasOpen = current.HasOpen || state == "open" || state == "opening"
	switch {
	case current.SawError:
		current.Item.State = "error"
	case current.HasOpen:
		current.Item.State = "open"
	case current.BlockedOnly:
		current.Item.State = "blocked"
	default:
		current.Item.State = "closed"
	}
	agg[key] = current
}

func pruneNoveltyAggregates(agg map[string]noveltyAggregate, limit int) {
	if limit <= 0 || len(agg) <= limit {
		return
	}
	type rankedNovelty struct {
		Key           string
		LastUpdatedAt time.Time
	}
	ranked := make([]rankedNovelty, 0, len(agg))
	for key, item := range agg {
		ranked = append(ranked, rankedNovelty{Key: key, LastUpdatedAt: item.Item.LastUpdatedAt})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].LastUpdatedAt.After(ranked[j].LastUpdatedAt) })
	for _, item := range ranked[limit:] {
		delete(agg, item.Key)
	}
}

func connectionNoveltyKey(item ConnectionRecord) string {
	app := strings.ToLower(strings.TrimSpace(item.ExePath))
	if app == "" && item.PID != 0 {
		app = fmt.Sprintf("pid:%d", item.PID)
	}
	if app == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(item.OriginalIP))
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(item.Hostname))
	}
	if host == "" || item.OriginalPort == 0 {
		return ""
	}
	return fmt.Sprintf("%s\x1f%s\x1f%d", app, host, item.OriginalPort)
}

func (s *Store) queryLogs(cutoff time.Time) ([]LogRecord, error) {
	files, err := s.segmentFiles("logs", cutoff)
	if err != nil {
		return nil, err
	}
	recent := make(logRecordMinHeap, 0, maxInitialLogQuery)
	for _, file := range files {
		if err := readSegmentFile(file, func(item LogRecord) {
			if item.Time.UTC().Before(cutoff) {
				return
			}
			if len(recent) < maxInitialLogQuery {
				heap.Push(&recent, item)
				return
			}
			if item.Time.After(recent[0].Time) {
				heap.Pop(&recent)
				heap.Push(&recent, item)
			}
		}, s.noteSkippedLine); err != nil {
			return nil, fmt.Errorf("query logs: %w", err)
		}
	}
	items := []LogRecord(recent)
	sort.Slice(items, func(i, j int) bool { return items[i].Time.After(items[j].Time) })
	return trimLogs(items), nil
}

type logRecordMinHeap []LogRecord

func (h logRecordMinHeap) Len() int { return len(h) }

func (h logRecordMinHeap) Less(i, j int) bool {
	return h[i].Time.Before(h[j].Time)
}

func (h logRecordMinHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *logRecordMinHeap) Push(x any) {
	*h = append(*h, x.(LogRecord))
}

func (h *logRecordMinHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func (s *Store) queryTraffic(cutoff time.Time, bucketSeconds int) ([]TrafficSample, TrafficTotals, error) {
	files, err := s.segmentFiles("traffic", cutoff)
	if err != nil {
		return nil, TrafficTotals{}, err
	}
	cutoff = cutoff.UTC().Truncate(time.Second)
	if bucketSeconds < 1 {
		bucketSeconds = 1
	}
	bucketWidth := int64(bucketSeconds)
	agg := map[int64]TrafficSample{}
	totals := TrafficTotals{}
	for _, file := range files {
		if err := readSegmentFile(file, func(item TrafficSample) {
			ts := item.Time.UTC()
			if ts.Before(cutoff) {
				return
			}
			totals.UpBytes += item.UpBytes
			totals.DownBytes += item.DownBytes
			key := ts.Unix()
			if bucketWidth > 1 {
				key = (key / bucketWidth) * bucketWidth
			}
			current := agg[key]
			if current.Time.Before(ts) {
				current.Time = ts
			}
			current.UpBytes += item.UpBytes
			current.DownBytes += item.DownBytes
			agg[key] = current
		}, s.noteSkippedLine); err != nil {
			return nil, TrafficTotals{}, fmt.Errorf("query traffic: %w", err)
		}
	}
	keys := make([]int64, 0, len(agg))
	for ts := range agg {
		keys = append(keys, ts)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]TrafficSample, 0, len(keys))
	for _, ts := range keys {
		item := agg[ts]
		out = append(out, item)
	}
	return out, totals, nil
}

func (s *Store) queryRuleStats(cutoff time.Time) ([]RuleActivity, error) {
	files, err := s.segmentFiles("rules", cutoff)
	if err != nil {
		return nil, err
	}
	agg := map[string]RuleActivity{}
	for _, file := range files {
		if err := readSegmentFile(file, func(item timedRuleActivity) {
			if item.Time.UTC().Before(cutoff) {
				return
			}
			if item.Connections == 0 && item.UpBytes == 0 && item.DownBytes == 0 {
				return
			}
			key := fmt.Sprintf("%s\x1f%s\x1f%s", strings.ToLower(strings.TrimSpace(item.RuleID)), strings.ToLower(strings.TrimSpace(item.RuleName)), strings.ToLower(strings.TrimSpace(string(item.Action))))
			current := agg[key]
			if current.RuleID == "" && current.RuleName == "" {
				current.RuleID = item.RuleID
				current.RuleName = item.RuleName
				current.Action = item.Action
			}
			current.Connections += item.Connections
			current.UpBytes += item.UpBytes
			current.DownBytes += item.DownBytes
			agg[key] = current
		}, s.noteSkippedLine); err != nil {
			return nil, fmt.Errorf("query rule stats: %w", err)
		}
	}
	out := make([]RuleActivity, 0, len(agg))
	for _, item := range agg {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Connections != out[j].Connections {
			return out[i].Connections > out[j].Connections
		}
		ai := out[i].UpBytes + out[i].DownBytes
		aj := out[j].UpBytes + out[j].DownBytes
		if ai != aj {
			return ai > aj
		}
		return strings.ToLower(out[i].RuleName) < strings.ToLower(out[j].RuleName)
	})
	return out, nil
}

func (s *Store) segmentFiles(prefix string, cutoff time.Time) ([]string, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("list history segments: %w", err)
	}
	type candidate struct {
		start time.Time
		path  string
	}
	files := make([]candidate, 0, 8)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix+"-") || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		start, ok := parseSegmentTime(entry.Name())
		if !ok {
			continue
		}
		if start.Add(time.Hour).Before(cutoff.UTC()) {
			continue
		}
		files = append(files, candidate{start: start, path: filepath.Join(s.root, entry.Name())})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].start.Before(files[j].start) })
	out := make([]string, 0, len(files))
	for _, item := range files {
		out = append(out, item.path)
	}
	return out, nil
}

func readSegmentFile[T any](path string, fn func(T), onSkipped func()) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 2<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var item T
		if err := json.Unmarshal(line, &item); err != nil {
			if onSkipped != nil {
				onSkipped()
			}
			continue
		}
		fn(item)
	}
	return scanner.Err()
}

func (s *Store) noteSkippedLine() {
	if s != nil {
		s.skippedLines.Add(1)
	}
}

func recoverJSONLTails(root string) (int64, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, fmt.Errorf("list history files for recovery: %w", err)
	}
	var recovered int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".jsonl") {
			continue
		}
		n, err := recoverJSONLTail(filepath.Join(root, entry.Name()))
		if err != nil {
			return recovered, err
		}
		recovered += n
	}
	return recovered, nil
}

func recoverJSONLTail(path string) (int64, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open history file for recovery: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat history file for recovery: %w", err)
	}
	size := info.Size()
	if size == 0 {
		return 0, nil
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], size-1); err != nil {
		return 0, fmt.Errorf("read history tail: %w", err)
	}
	if last[0] == '\n' {
		return 0, nil
	}
	buf := make([]byte, 64*1024)
	pos := size
	for pos > 0 {
		start := pos - int64(len(buf))
		if start < 0 {
			start = 0
		}
		n, readErr := f.ReadAt(buf[:pos-start], start)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return 0, fmt.Errorf("scan history tail: %w", readErr)
		}
		if idx := bytes.LastIndexByte(buf[:n], '\n'); idx >= 0 {
			keep := start + int64(idx) + 1
			if err := f.Truncate(keep); err != nil {
				return 0, fmt.Errorf("truncate corrupt history tail: %w", err)
			}
			return size - keep, nil
		}
		pos = start
	}
	if err := f.Truncate(0); err != nil {
		return 0, fmt.Errorf("truncate corrupt history file: %w", err)
	}
	return size, nil
}

func connectionAggregateKey(item ConnectionRecord) string {
	return fmt.Sprintf("%d\x1f%s\x1f%s\x1f%d\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s",
		item.PID,
		item.ExePath,
		item.OriginalIP,
		item.OriginalPort,
		item.Hostname,
		item.RuleID,
		item.RuleName,
		item.Action,
		item.ProxyID,
		item.ChainID,
	)
}

func (s *Store) droppedPath() string {
	return filepath.Join(s.root, "dropped.jsonl")
}

func droppedSearchTokens(raw string) []string {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(raw)))
	if len(fields) == 0 {
		return nil
	}
	out := fields[:0]
	for _, field := range fields {
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func droppedMatchesSearch(item DroppedRecord, tokens []string) bool {
	if len(tokens) == 0 {
		return true
	}
	text := droppedSearchText(item)
	for _, token := range tokens {
		if !strings.Contains(text, token) {
			return false
		}
	}
	return true
}

func droppedSearchText(item DroppedRecord) string {
	c := item.Connection
	return strings.ToLower(strings.Join([]string{
		item.DropID,
		item.DroppedAt.Format(time.RFC3339),
		fmt.Sprintf("%d", c.PID),
		filepath.Base(c.ExePath),
		c.ExePath,
		c.SourceIP,
		fmt.Sprintf("%d", c.SourcePort),
		c.OriginalIP,
		fmt.Sprintf("%d", c.OriginalPort),
		c.Hostname,
		c.RuleID,
		c.RuleName,
		string(c.Action),
		c.ProxyID,
		c.ChainID,
		c.State,
	}, " \x1f "))
}

func segmentRoot(path string) string {
	ext := filepath.Ext(path)
	if strings.EqualFold(ext, ".sqlite") {
		return strings.TrimSuffix(path, ext)
	}
	if ext == "" {
		return path
	}
	return path + ".segments"
}

func segmentFileName(prefix string, ts time.Time) string {
	return fmt.Sprintf("%s-%s.jsonl", prefix, ts.UTC().Truncate(time.Hour).Format(segmentLayout))
}

func parseSegmentTime(name string) (time.Time, bool) {
	base := strings.TrimSuffix(filepath.Base(name), ".jsonl")
	_, stamp, ok := strings.Cut(base, "-")
	if !ok {
		return time.Time{}, false
	}
	ts, err := time.ParseInLocation(segmentLayout, stamp, time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return ts.UTC(), true
}

func trimLogs(items []LogRecord) []LogRecord {
	if len(items) == 0 {
		return nil
	}
	const (
		processKeep = 100
		genericKeep = 200
	)
	perProcess := map[uint32]int{}
	genericCount := 0
	kept := make([]LogRecord, 0, len(items))
	for _, item := range items {
		if item.PID != 0 {
			if perProcess[item.PID] >= processKeep {
				continue
			}
			perProcess[item.PID]++
		} else {
			if genericCount >= genericKeep {
				continue
			}
			genericCount++
		}
		kept = append(kept, item)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Time.Before(kept[j].Time) })
	return kept
}
