package history

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openai/pitchprox/internal/config"
)

type Store struct {
	root string

	mu                 sync.Mutex
	flushMu            sync.Mutex
	pendingLogs        []LogRecord
	pendingConnections []ConnectionRecord
	pendingTraffic     map[int64]TrafficSample
	pendingRule        map[string]rulePending
	retention          atomic.Int64
	lastPrune          time.Time
	wake               chan struct{}
	stop               chan struct{}
	wg                 sync.WaitGroup
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

type SnapshotOptions struct {
	IncludeLogs          bool
	TrafficBucketSeconds int
}

const (
	flushInterval      = 3 * time.Second
	pruneInterval      = time.Minute
	maxInitialLogQuery = 5000
	segmentLayout      = "2006010215"
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
		stop:           make(chan struct{}),
	}
	s.SetRetentionWindow(retention)
	s.wg.Add(1)
	go s.loop()
	return s, nil
}

func (s *Store) Close() error {
	close(s.stop)
	s.wg.Wait()
	return nil
}

func (s *Store) SetRetentionWindow(d time.Duration) {
	if d < time.Minute {
		d = 7 * time.Minute
	}
	s.retention.Store(int64(d))
	s.wakeFlush()
}

func (s *Store) RecordLog(entry LogRecord) {
	s.mu.Lock()
	s.pendingLogs = append(s.pendingLogs, entry)
	count := len(s.pendingLogs)
	s.mu.Unlock()
	if count >= 64 {
		s.wakeFlush()
	}
}

func (s *Store) RecordConnection(entry ConnectionRecord) {
	s.mu.Lock()
	s.pendingConnections = append(s.pendingConnections, entry)
	count := len(s.pendingConnections)
	s.mu.Unlock()
	if count >= 64 {
		s.wakeFlush()
	}
}

func (s *Store) AddTraffic(ts time.Time, upBytes, downBytes int64) {
	if upBytes == 0 && downBytes == 0 {
		return
	}
	bucket := ts.UTC().Truncate(time.Second)
	key := bucket.Unix()
	s.mu.Lock()
	item := s.pendingTraffic[key]
	if item.Time.IsZero() {
		item.Time = bucket
	}
	item.UpBytes += upBytes
	item.DownBytes += downBytes
	s.pendingTraffic[key] = item
	s.mu.Unlock()
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
	item := s.pendingRule[key]
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

func (s *Store) Flush() error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	s.mu.Lock()
	logs := append([]LogRecord(nil), s.pendingLogs...)
	conns := append([]ConnectionRecord(nil), s.pendingConnections...)
	traffic := s.pendingTraffic
	rules := s.pendingRule
	if len(logs) == 0 && len(conns) == 0 && len(traffic) == 0 && len(rules) == 0 && time.Since(s.lastPrune) < pruneInterval {
		s.mu.Unlock()
		return nil
	}
	s.pendingLogs = nil
	s.pendingConnections = nil
	s.pendingTraffic = map[int64]TrafficSample{}
	s.pendingRule = map[string]rulePending{}
	shouldPrune := time.Since(s.lastPrune) >= pruneInterval
	if shouldPrune {
		s.lastPrune = time.Now().UTC()
	}
	s.mu.Unlock()

	if err := s.appendLogs(logs); err != nil {
		return err
	}
	if err := s.appendConnections(conns); err != nil {
		return err
	}
	if err := s.appendTraffic(traffic); err != nil {
		return err
	}
	if err := s.appendRules(rules); err != nil {
		return err
	}
	if shouldPrune {
		if err := s.pruneSegments(time.Now().UTC().Add(-time.Duration(s.retention.Load()))); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			_ = s.Flush()
			return
		case <-ticker.C:
			_ = s.Flush()
		case <-s.wake:
			_ = s.Flush()
		}
	}
}

func (s *Store) wakeFlush() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
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
	keys := make([]string, 0, len(buffers))
	for key := range buffers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		path := filepath.Join(s.root, key)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("open history segment %s: %w", key, err)
		}
		if _, err := f.Write(buffers[key].Bytes()); err != nil {
			_ = f.Close()
			return fmt.Errorf("write history segment %s: %w", key, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close history segment %s: %w", key, err)
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
	agg := map[string]connectionAggregate{}
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
		}); err != nil {
			return nil, fmt.Errorf("query connections: %w", err)
		}
	}
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

func (s *Store) queryLogs(cutoff time.Time) ([]LogRecord, error) {
	files, err := s.segmentFiles("logs", cutoff)
	if err != nil {
		return nil, err
	}
	items := make([]LogRecord, 0, 128)
	for _, file := range files {
		if err := readSegmentFile(file, func(item LogRecord) {
			if item.Time.UTC().Before(cutoff) {
				return
			}
			items = append(items, item)
		}); err != nil {
			return nil, fmt.Errorf("query logs: %w", err)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Time.After(items[j].Time) })
	if len(items) > maxInitialLogQuery {
		items = items[:maxInitialLogQuery]
	}
	return trimLogs(items), nil
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
	cutoffUnix := cutoff.Unix()
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
				key = cutoffUnix + ((key-cutoffUnix)/bucketWidth)*bucketWidth
			}
			current := agg[key]
			if current.Time.Before(ts) {
				current.Time = ts
			}
			current.UpBytes += item.UpBytes
			current.DownBytes += item.DownBytes
			agg[key] = current
		}); err != nil {
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
		}); err != nil {
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

func readSegmentFile[T any](path string, fn func(T)) error {
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
			return err
		}
		fn(item)
	}
	return scanner.Err()
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
