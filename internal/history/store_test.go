package history

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
)

func TestStoreSnapshotRoundTrip(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pitchProx.history")
	store, err := Open(root, 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	now := time.Now().UTC().Truncate(time.Second)
	store.RecordLog(LogRecord{
		Time:    now,
		Level:   "info",
		Message: "opened",
		PID:     42,
	})
	store.RecordConnection(ConnectionRecord{
		ID:            "conn-1",
		PID:           42,
		ExePath:       "demo.exe",
		OriginalIP:    "1.1.1.1",
		OriginalPort:  443,
		RuleID:        "default",
		RuleName:      "Default",
		Action:        config.ActionDirect,
		State:         "closed",
		BytesUp:       10,
		BytesDown:     20,
		CreatedAt:     now,
		LastUpdatedAt: now,
		Count:         1,
	})
	store.AddTraffic(now, 100, 200)
	store.AddRuleActivity(now, "default", "Default", config.ActionDirect, 1, 100, 200)

	if err := store.Flush(); err != nil {
		t.Fatalf("flush store: %v", err)
	}

	snap, err := store.Snapshot(10 * time.Minute)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	if got := len(snap.Logs); got != 1 {
		t.Fatalf("logs len = %d, want 1", got)
	}
	if got := len(snap.Connections); got != 1 {
		t.Fatalf("connections len = %d, want 1", got)
	}
	if got := len(snap.Traffic); got != 1 {
		t.Fatalf("traffic len = %d, want 1", got)
	}
	if got := len(snap.RuleStats); got != 1 {
		t.Fatalf("rule stats len = %d, want 1", got)
	}
	if snap.TrafficTotals.UpBytes != 100 || snap.TrafficTotals.DownBytes != 200 {
		t.Fatalf("traffic totals = %+v, want up=100 down=200", snap.TrafficTotals)
	}
	if snap.Connections[0].BytesUp != 10 || snap.Connections[0].BytesDown != 20 {
		t.Fatalf("connection bytes = up=%d down=%d, want up=10 down=20", snap.Connections[0].BytesUp, snap.Connections[0].BytesDown)
	}
	if snap.RuleStats[0].Connections != 1 {
		t.Fatalf("rule connections = %d, want 1", snap.RuleStats[0].Connections)
	}
}

func TestRuleActivityTimelineIsBoundedAndUsesStableRuleID(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "pitchProx.history"), 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	store.AddRuleActivity(now.Add(-40*time.Second), "rule-1", "Old name", config.ActionProxy, 1, 100, 200)
	store.AddRuleActivity(now.Add(-10*time.Second), "rule-1", "New name", config.ActionDirect, 2, 300, 400)
	store.AddRuleActivity(now.Add(-10*time.Second), "other", "Other", config.ActionProxy, 9, 900, 900)
	if err := store.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	timeline, err := store.RuleActivityTimeline([]string{"rule-1", "rule-1"}, 5*time.Minute, 40)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if timeline.Points != 40 || timeline.BucketSeconds < 1 {
		t.Fatalf("unexpected timeline bounds: %+v", timeline)
	}
	if len(timeline.Series) != 1 {
		t.Fatalf("series count = %d, want 1", len(timeline.Series))
	}
	series := timeline.Series[0]
	if series.Connections != 3 || series.UpBytes != 400 || series.DownBytes != 600 {
		t.Fatalf("series totals = %+v", series)
	}
	if series.RuleName != "New name" || series.Action != config.ActionDirect {
		t.Fatalf("series metadata = %+v, want newest name/action", series)
	}
	if len(series.Buckets) != 40 {
		t.Fatalf("bucket count = %d, want 40", len(series.Buckets))
	}
	var connections int64
	for _, bucket := range series.Buckets {
		connections += bucket.Connections
	}
	if connections != 3 {
		t.Fatalf("bucket connections = %d, want 3", connections)
	}
}

func TestRuleActivityTimelinePendingMetadataWinsSameWriteBucket(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "pitchProx.history"), 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ts := time.Now().UTC().Truncate(ruleActivityWriteBucket)
	store.AddRuleActivity(ts, "rule", "Flushed name", config.ActionProxy, 1, 10, 20)
	if err := store.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	store.AddRuleActivity(ts, "rule", "Pending name", config.ActionDirect, 2, 30, 40)

	timeline, err := store.RuleActivityTimeline([]string{"rule"}, time.Minute, 40)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	series := timeline.Series[0]
	if series.Connections != 3 || series.UpBytes != 40 || series.DownBytes != 60 {
		t.Fatalf("series totals = %+v", series)
	}
	if series.RuleName != "Pending name" || series.Action != config.ActionDirect {
		t.Fatalf("series metadata = %+v, want pending name/action", series)
	}
}

func TestRuleActivityAggregateKeepsLatestRealEventTime(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "pitchProx.history"), 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	older := time.Date(2026, 8, 3, 12, 0, 16, 900_000_000, time.UTC)
	newer := older.Add(11 * time.Second)
	store.AddRuleActivity(older, "rule", "Older", config.ActionProxy, 1, 0, 0)
	store.AddRuleActivity(newer, "rule", "Newer", config.ActionDirect, 1, 0, 0)
	// An out-of-order event may contribute counters but must not move the
	// representative timestamp or metadata backwards.
	store.AddRuleActivity(older.Add(time.Second), "rule", "Late old event", config.ActionBlock, 1, 0, 0)

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.pendingRule) != 1 {
		t.Fatalf("pending rule buckets = %d, want 1", len(store.pendingRule))
	}
	for _, item := range store.pendingRule {
		if item.Ts != newer.Truncate(time.Second).Unix() {
			t.Fatalf("aggregate timestamp = %d, want latest real event %d", item.Ts, newer.Truncate(time.Second).Unix())
		}
		if item.Item.RuleName != "Newer" || item.Item.Action != config.ActionDirect || item.Item.Connections != 3 {
			t.Fatalf("aggregate = %+v, want latest metadata and all counters", item.Item)
		}
	}
}

func TestRuleActivityReverseScanFinishesBoundaryWriteBucket(t *testing.T) {
	cutoff := time.Date(2026, 8, 3, 12, 0, 10, 0, time.UTC)
	if ruleActivityBucketBeforeCutoff(time.Date(2026, 8, 3, 12, 0, 1, 0, time.UTC), cutoff) {
		t.Fatal("scan would stop inside the cutoff's partial write bucket")
	}
	if !ruleActivityBucketBeforeCutoff(time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC).Add(-time.Second), cutoff) {
		t.Fatal("scan would continue into a write bucket entirely before cutoff")
	}
}

func TestRuleActivityTimelineIncludesPendingAndPreservesOpaqueRuleIDs(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "pitchProx.history"), 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	longID := strings.Repeat("long-id-", 40)
	ids := []string{"Foo", "foo", "foo,bar", longID}
	for i, id := range ids {
		store.AddRuleActivity(now, id, id, config.ActionDirect, int64(i+1), 0, 0)
	}

	// Deliberately do not Flush: the endpoint must merge a stable copy of the
	// bounded pending map rather than force an extra disk write.
	timeline, err := store.RuleActivityTimeline(ids, time.Minute, 40)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if len(timeline.Series) != len(ids) {
		t.Fatalf("series count = %d, want %d", len(timeline.Series), len(ids))
	}
	for i, series := range timeline.Series {
		if series.RuleID != ids[i] || series.Connections != int64(i+1) {
			t.Fatalf("series %d = %+v, want id=%q connections=%d", i, series, ids[i], i+1)
		}
	}
	if timeline.WindowMinutes != 1 || timeline.BucketSeconds != 1.5 {
		t.Fatalf("timeline window = %d minutes, bucket=%v seconds", timeline.WindowMinutes, timeline.BucketSeconds)
	}
}

func TestRuleActivityTimelineDoesNotExpandRequestedWindow(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "pitchProx.history"), 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	store.AddRuleActivity(now.Add(-70*time.Second), "rule", "Old", config.ActionDirect, 100, 0, 0)
	store.AddRuleActivity(now.Add(-5*time.Second), "rule", "Recent", config.ActionDirect, 1, 0, 0)
	timeline, err := store.RuleActivityTimeline([]string{"rule"}, time.Minute, 40)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if got := timeline.Series[0].Connections; got != 1 {
		t.Fatalf("connections in exact one-minute window = %d, want 1", got)
	}
}

func TestRuleStatsAggregateRenameAndActionByExactStableID(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "pitchProx.history"), 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	store.AddRuleActivity(now.Add(-30*time.Second), "Stable", "Old name", config.ActionProxy, 1, 10, 20)
	store.AddRuleActivity(now, "Stable", "New name", config.ActionDirect, 2, 30, 40)
	store.AddRuleActivity(now, "stable", "Different exact ID", config.ActionBlock, 4, 50, 60)
	snapshot, err := store.Snapshot(10 * time.Minute)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snapshot.RuleStats) != 2 {
		t.Fatalf("rule stats count = %d, want 2: %+v", len(snapshot.RuleStats), snapshot.RuleStats)
	}
	var stable RuleActivity
	for _, item := range snapshot.RuleStats {
		if item.RuleID == "Stable" {
			stable = item
		}
	}
	if stable.Connections != 3 || stable.UpBytes != 40 || stable.DownBytes != 60 {
		t.Fatalf("stable aggregate = %+v", stable)
	}
	if stable.RuleName != "New name" || stable.Action != config.ActionDirect {
		t.Fatalf("stable latest metadata = %+v", stable)
	}
}

func TestRuleActivityTimelineAllowsConcurrentAppendAndFlush(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "pitchProx.history"), 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	done := make(chan error, 1)
	go func() {
		for i := 0; i < 100; i++ {
			store.AddRuleActivity(time.Now().UTC(), "rule", "Rule", config.ActionDirect, 1, 0, 0)
			if i%10 == 0 {
				if err := store.Flush(); err != nil {
					done <- err
					return
				}
			}
		}
		done <- store.Flush()
	}()
	for i := 0; i < 25; i++ {
		if _, err := store.RuleActivityTimeline([]string{"rule"}, time.Minute, 40); err != nil {
			t.Fatalf("timeline during append: %v", err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("writer: %v", err)
	}
	timeline, err := store.RuleActivityTimeline([]string{"rule"}, time.Minute, 40)
	if err != nil {
		t.Fatalf("final timeline: %v", err)
	}
	if got := timeline.Series[0].Connections; got != 100 {
		t.Fatalf("final connections = %d, want 100", got)
	}
}

func BenchmarkRuleActivityTimelineLargeSegment(b *testing.B) {
	store, err := Open(filepath.Join(b.TempDir(), "pitchProx.history"), time.Hour)
	if err != nil {
		b.Fatalf("open store: %v", err)
	}
	b.Cleanup(func() { _ = store.Close() })

	base := time.Now().UTC().Add(-15 * time.Minute)
	ids := make([]string, 50)
	for i := range ids {
		ids[i] = fmt.Sprintf("rule-%d", i)
	}
	for bucket := 0; bucket < 60; bucket++ {
		for rule := 0; rule < 74; rule++ {
			store.AddRuleActivity(base.Add(time.Duration(bucket)*15*time.Second), fmt.Sprintf("rule-%d", rule), "Rule", config.ActionProxy, 1, 128, 256)
		}
		if bucket == 29 {
			if err := store.Flush(); err != nil {
				b.Fatalf("flush first half: %v", err)
			}
		}
	}
	if err := store.Flush(); err != nil {
		b.Fatalf("flush: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.RuleActivityTimeline(ids, 15*time.Minute, 40); err != nil {
			b.Fatalf("timeline: %v", err)
		}
	}
}

func TestStoreRecoversPartialTailAndSkipsMalformedCompleteLine(t *testing.T) {
	root := filepath.Join(t.TempDir(), "history")
	now := time.Now().UTC().Truncate(time.Second)

	store, err := Open(root, 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	store.RecordLog(LogRecord{Time: now, Level: "info", Message: "valid"})
	if err := store.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	path := filepath.Join(root, segmentFileName("logs", now))
	partial := []byte(`{"time":"unfinished`)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open log segment for corruption: %v", err)
	}
	if _, err := f.Write(append([]byte("{malformed}\n"), partial...)); err != nil {
		_ = f.Close()
		t.Fatalf("append corrupt records: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close corrupt segment: %v", err)
	}

	reopened, err := Open(root, 10*time.Minute)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("close reopened store: %v", err)
		}
	}()

	if got := reopened.DiagnosticStats().RecoveredTailBytes; got != int64(len(partial)) {
		t.Fatalf("recovered tail bytes = %d, want %d", got, len(partial))
	}
	snapshot, err := reopened.Snapshot(10 * time.Minute)
	if err != nil {
		t.Fatalf("snapshot recovered store: %v", err)
	}
	if len(snapshot.Logs) != 1 || snapshot.Logs[0].Message != "valid" {
		t.Fatalf("recovered logs = %+v, want the valid record only", snapshot.Logs)
	}
	if got := reopened.DiagnosticStats().SkippedLines; got != 1 {
		t.Fatalf("skipped malformed lines = %d, want 1", got)
	}
}

func TestPendingHistoryIsBoundedWhenWriterCannotDrain(t *testing.T) {
	store := &Store{
		pendingTraffic: map[int64]TrafficSample{},
		pendingRule:    map[string]rulePending{},
	}
	base := time.Now().UTC().Truncate(time.Second)

	for i := 0; i < maxPendingLogs+10; i++ {
		store.RecordLog(LogRecord{Time: base, Message: fmt.Sprintf("log-%d", i)})
	}
	for i := 0; i < maxPendingConnections+10; i++ {
		store.RecordConnection(ConnectionRecord{ID: fmt.Sprintf("conn-%d", i)})
	}
	for i := 0; i < maxPendingDropped+10; i++ {
		store.RecordDroppedConnection(ConnectionRecord{ID: fmt.Sprintf("drop-%d", i), LastUpdatedAt: base})
	}
	for i := 0; i < maxPendingTrafficBuckets+10; i++ {
		store.AddTraffic(base.Add(time.Duration(i)*time.Second), 1, 1)
	}
	for i := 0; i < maxPendingRuleBuckets+10; i++ {
		store.AddRuleActivity(base, fmt.Sprintf("rule-%d", i), "", config.ActionDirect, 1, 0, 0)
	}

	stats := store.DiagnosticStats()
	if stats.PendingLogs != maxPendingLogs ||
		stats.PendingConnections != maxPendingConnections ||
		stats.PendingDropped != maxPendingDropped ||
		stats.PendingTrafficBuckets != maxPendingTrafficBuckets ||
		stats.PendingRuleBuckets != maxPendingRuleBuckets {
		t.Fatalf("pending queues exceeded limits: %+v", stats)
	}
	if stats.DiscardedPending != 50 {
		t.Fatalf("discarded pending records = %d, want 50", stats.DiscardedPending)
	}
}

func TestStoreSnapshotWithoutLogs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pitchProx.history")
	store, err := Open(root, 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	now := time.Now().UTC().Truncate(time.Second)
	store.RecordLog(LogRecord{
		Time:    now,
		Level:   "info",
		Message: "hidden",
		PID:     77,
	})
	store.RecordConnection(ConnectionRecord{
		ID:            "conn-2",
		PID:           77,
		ExePath:       "worker.exe",
		OriginalIP:    "8.8.8.8",
		OriginalPort:  53,
		Action:        config.ActionDirect,
		State:         "closed",
		CreatedAt:     now,
		LastUpdatedAt: now,
		Count:         1,
	})

	if err := store.Flush(); err != nil {
		t.Fatalf("flush store: %v", err)
	}

	snap, err := store.SnapshotWithOptions(10*time.Minute, SnapshotOptions{IncludeLogs: false})
	if err != nil {
		t.Fatalf("snapshot without logs: %v", err)
	}

	if got := len(snap.Logs); got != 0 {
		t.Fatalf("logs len = %d, want 0 when logs are excluded", got)
	}
	if got := len(snap.Connections); got != 1 {
		t.Fatalf("connections len = %d, want 1", got)
	}
}

func TestStoreSnapshotBucketsTraffic(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pitchProx.history")
	store, err := Open(root, 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	baseUnix := time.Now().UTC().Add(-2 * time.Minute).Unix()
	base := time.Unix((baseUnix/3)*3, 0).UTC()
	store.AddTraffic(base.Add(0*time.Second), 10, 100)
	store.AddTraffic(base.Add(1*time.Second), 20, 200)
	store.AddTraffic(base.Add(2*time.Second), 30, 300)
	store.AddTraffic(base.Add(3*time.Second), 40, 400)

	if err := store.Flush(); err != nil {
		t.Fatalf("flush store: %v", err)
	}

	snap, err := store.SnapshotWithOptions(10*time.Minute, SnapshotOptions{
		IncludeLogs:          false,
		TrafficBucketSeconds: 3,
	})
	if err != nil {
		t.Fatalf("snapshot with traffic buckets: %v", err)
	}

	if got := len(snap.Traffic); got != 2 {
		t.Fatalf("traffic len = %d, want 2", got)
	}
	if got := snap.Traffic[0].UpBytes; got != 60 {
		t.Fatalf("first bucket up = %d, want 60", got)
	}
	if got := snap.Traffic[0].DownBytes; got != 600 {
		t.Fatalf("first bucket down = %d, want 600", got)
	}
	if got := snap.Traffic[1].UpBytes; got != 40 {
		t.Fatalf("second bucket up = %d, want 40", got)
	}
	if got := snap.Traffic[1].DownBytes; got != 400 {
		t.Fatalf("second bucket down = %d, want 400", got)
	}
	if snap.TrafficTotals.UpBytes != 100 || snap.TrafficTotals.DownBytes != 1000 {
		t.Fatalf("traffic totals = %+v, want up=100 down=1000", snap.TrafficTotals)
	}
}

func TestStoreSnapshotCapsHistoryPayload(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pitchProx.history")
	store, err := Open(root, 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	base := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	totalConnections := connectionQueryPruneTrigger + 100
	for i := 0; i < totalConnections; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		store.RecordConnection(ConnectionRecord{
			ID:            fmt.Sprintf("conn-%d", i),
			PID:           uint32(i + 1),
			ExePath:       "demo.exe",
			OriginalIP:    "203.0.113.10",
			OriginalPort:  uint16(1000 + i),
			Action:        config.ActionDirect,
			State:         "closed",
			CreatedAt:     ts,
			LastUpdatedAt: ts,
			Count:         1,
		})
	}

	totalLogs := maxInitialLogQuery + 100
	for i := 0; i < totalLogs; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		store.RecordLog(LogRecord{
			Time:    ts,
			Level:   "info",
			Message: fmt.Sprintf("log-%d", i),
			PID:     uint32(i + 1),
		})
	}

	if err := store.Flush(); err != nil {
		t.Fatalf("flush store: %v", err)
	}

	snap, err := store.Snapshot(10 * time.Minute)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	if got := len(snap.Connections); got != maxInitialConnectionQuery {
		t.Fatalf("connections len = %d, want capped %d", got, maxInitialConnectionQuery)
	}
	if got := snap.Connections[0].ID; got != fmt.Sprintf("conn-%d", totalConnections-1) {
		t.Fatalf("newest connection = %q, want latest", got)
	}
	if got := len(snap.Logs); got != maxInitialLogQuery {
		t.Fatalf("logs len = %d, want capped %d", got, maxInitialLogQuery)
	}
	if got := snap.Logs[0].Message; got != "log-100" {
		t.Fatalf("oldest kept log = %q, want log-100", got)
	}
	if got := snap.Logs[len(snap.Logs)-1].Message; got != fmt.Sprintf("log-%d", totalLogs-1) {
		t.Fatalf("newest kept log = %q, want latest", got)
	}
}

func TestStoreNewConnectionsUsesBaseline(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pitchProx.history")
	store, err := Open(root, 7*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	now := time.Now().UTC().Truncate(time.Second)
	exe := `C:\Apps\demo.exe`
	store.RecordConnection(ConnectionRecord{
		ID:            "old-same",
		PID:           101,
		ExePath:       exe,
		OriginalIP:    "198.51.100.10",
		OriginalPort:  443,
		Action:        config.ActionDirect,
		State:         "closed",
		CreatedAt:     now.Add(-3 * time.Minute),
		LastUpdatedAt: now.Add(-3 * time.Minute),
		Count:         1,
	})
	store.RecordConnection(ConnectionRecord{
		ID:            "recent-same-new-pid",
		PID:           202,
		ExePath:       exe,
		OriginalIP:    "198.51.100.10",
		OriginalPort:  443,
		Action:        config.ActionDirect,
		State:         "closed",
		CreatedAt:     now.Add(-30 * time.Second),
		LastUpdatedAt: now.Add(-30 * time.Second),
		Count:         1,
	})
	store.RecordConnection(ConnectionRecord{
		ID:            "recent-new",
		PID:           202,
		ExePath:       exe,
		OriginalIP:    "203.0.113.20",
		OriginalPort:  443,
		Action:        config.ActionDirect,
		State:         "closed",
		CreatedAt:     now.Add(-30 * time.Second),
		LastUpdatedAt: now.Add(-30 * time.Second),
		Count:         1,
	})
	store.RecordConnection(ConnectionRecord{
		ID:            "outside-baseline-old",
		PID:           202,
		ExePath:       exe,
		OriginalIP:    "192.0.2.55",
		OriginalPort:  443,
		Action:        config.ActionDirect,
		State:         "closed",
		CreatedAt:     now.Add(-10 * time.Minute),
		LastUpdatedAt: now.Add(-10 * time.Minute),
		Count:         1,
	})
	store.RecordConnection(ConnectionRecord{
		ID:            "outside-baseline-recent",
		PID:           202,
		ExePath:       exe,
		OriginalIP:    "192.0.2.55",
		OriginalPort:  443,
		Action:        config.ActionDirect,
		State:         "closed",
		CreatedAt:     now.Add(-30 * time.Second),
		LastUpdatedAt: now.Add(-30 * time.Second),
		Count:         1,
	})

	items, err := store.NewConnections(NewConnectionOptions{
		Baseline: 7 * time.Minute,
		Recent:   time.Minute,
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("new connections: %v", err)
	}

	got := map[string]bool{}
	for _, item := range items {
		got[item.OriginalIP] = true
	}
	if got["198.51.100.10"] {
		t.Fatal("same exe/address/port with a different recent PID was reported as new")
	}
	for _, ip := range []string{"203.0.113.20", "192.0.2.55"} {
		if !got[ip] {
			t.Fatalf("new connection %s was not reported; got %+v", ip, items)
		}
	}
	if len(items) != 2 {
		t.Fatalf("new connections len = %d, want 2: %+v", len(items), items)
	}
}

func TestStoreNewConnectionsIncludesLiveRecords(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pitchProx.history")
	store, err := Open(root, 7*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	now := time.Now().UTC().Truncate(time.Second)
	exe := `C:\Apps\live.exe`
	store.RecordConnection(ConnectionRecord{
		ID:            "history-same",
		PID:           303,
		ExePath:       exe,
		OriginalIP:    "198.51.100.30",
		OriginalPort:  443,
		Action:        config.ActionDirect,
		State:         "closed",
		CreatedAt:     now.Add(-2 * time.Minute),
		LastUpdatedAt: now.Add(-2 * time.Minute),
		Count:         1,
	})

	items, err := store.NewConnections(NewConnectionOptions{
		Baseline: 7 * time.Minute,
		Recent:   time.Minute,
		Limit:    10,
		Live: []ConnectionRecord{
			{
				ID:            "live-suppressed",
				PID:           404,
				ExePath:       exe,
				OriginalIP:    "198.51.100.30",
				OriginalPort:  443,
				Action:        config.ActionDirect,
				State:         "open",
				CreatedAt:     now,
				LastUpdatedAt: now,
				Count:         1,
			},
			{
				ID:            "live-new",
				PID:           404,
				ExePath:       exe,
				OriginalIP:    "203.0.113.40",
				OriginalPort:  443,
				Action:        config.ActionDirect,
				State:         "open",
				CreatedAt:     now,
				LastUpdatedAt: now,
				Count:         1,
			},
		},
	})
	if err != nil {
		t.Fatalf("new connections: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("new connections len = %d, want 1: %+v", len(items), items)
	}
	if items[0].OriginalIP != "203.0.113.40" {
		t.Fatalf("new live connection = %s, want 203.0.113.40", items[0].OriginalIP)
	}
	if items[0].State != "open" {
		t.Fatalf("new live connection state = %q, want open", items[0].State)
	}
}

func TestStoreNewConnectionsRequiresWindowLongerThanRecent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pitchProx.history")
	store, err := Open(root, time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	now := time.Now().UTC().Truncate(time.Second)
	store.RecordConnection(ConnectionRecord{
		ID:            "recent",
		PID:           505,
		ExePath:       `C:\Apps\short.exe`,
		OriginalIP:    "203.0.113.50",
		OriginalPort:  443,
		Action:        config.ActionDirect,
		State:         "closed",
		CreatedAt:     now.Add(-30 * time.Second),
		LastUpdatedAt: now.Add(-30 * time.Second),
		Count:         1,
	})

	items, err := store.NewConnections(NewConnectionOptions{
		Baseline: time.Minute,
		Recent:   time.Minute,
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("new connections: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("new connections len = %d, want 0 when baseline is not longer than recent: %+v", len(items), items)
	}
}

func TestStoreDroppedConnectionsSearchPaginationAndDelete(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pitchProx.history")
	store, err := Open(root, 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		ts := now.Add(time.Duration(i) * time.Second)
		store.RecordDroppedConnection(ConnectionRecord{
			ID:            fmt.Sprintf("blocked-%d", i),
			PID:           uint32(900 + i),
			ExePath:       fmt.Sprintf(`C:\Apps\blocked-%d.exe`, i),
			OriginalIP:    fmt.Sprintf("203.0.113.%d", i+1),
			OriginalPort:  443,
			Hostname:      fmt.Sprintf("blocked-%d.example", i),
			RuleID:        "deny",
			RuleName:      "Deny rule",
			Action:        config.ActionBlock,
			State:         "blocked",
			CreatedAt:     ts,
			LastUpdatedAt: ts,
			Count:         1,
		})
	}
	if err := store.Flush(); err != nil {
		t.Fatalf("flush store: %v", err)
	}

	all, err := store.DroppedConnections(DroppedQuery{Limit: 2})
	if err != nil {
		t.Fatalf("dropped connections: %v", err)
	}
	if all.Total != 3 || len(all.Items) != 2 {
		t.Fatalf("dropped page total=%d len=%d, want total=3 len=2", all.Total, len(all.Items))
	}
	if all.Items[0].Connection.ID != "blocked-2" {
		t.Fatalf("newest dropped id = %q, want blocked-2", all.Items[0].Connection.ID)
	}

	filtered, err := store.DroppedConnections(DroppedQuery{Search: "blocked-1 443 deny", Limit: 100})
	if err != nil {
		t.Fatalf("filtered dropped connections: %v", err)
	}
	if filtered.Total != 1 || filtered.Items[0].Connection.ID != "blocked-1" {
		t.Fatalf("filtered dropped = total %d items %+v, want blocked-1", filtered.Total, filtered.Items)
	}

	if err := store.DeleteDroppedConnections([]string{filtered.Items[0].DropID}); err != nil {
		t.Fatalf("delete dropped: %v", err)
	}
	afterDelete, err := store.DroppedConnections(DroppedQuery{Search: "blocked-1", Limit: 100})
	if err != nil {
		t.Fatalf("dropped after delete: %v", err)
	}
	if afterDelete.Total != 0 {
		t.Fatalf("deleted dropped total = %d, want 0", afterDelete.Total)
	}
}

func TestStoreDroppedConnectionsHonorsSizeLimit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pitchProx.history")
	store, err := Open(root, 10*time.Minute)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()
	store.SetDroppedLogMaxBytes(2 * 1024)

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 40; i++ {
		ts := now.Add(time.Duration(i) * time.Second)
		store.RecordDroppedConnection(ConnectionRecord{
			ID:            fmt.Sprintf("limited-%02d", i),
			PID:           uint32(1200 + i),
			ExePath:       fmt.Sprintf(`C:\VeryLongApplicationPath\limited-%02d-worker-with-extra-context.exe`, i),
			OriginalIP:    fmt.Sprintf("198.51.100.%d", i+1),
			OriginalPort:  uint16(1000 + i),
			Hostname:      fmt.Sprintf("limited-%02d.example.test", i),
			RuleID:        "limited-deny",
			RuleName:      "Limited deny",
			Action:        config.ActionBlock,
			State:         "blocked",
			CreatedAt:     ts,
			LastUpdatedAt: ts,
			Count:         1,
		})
	}
	if err := store.Flush(); err != nil {
		t.Fatalf("flush store: %v", err)
	}

	result, err := store.DroppedConnections(DroppedQuery{Limit: 100})
	if err != nil {
		t.Fatalf("dropped limited: %v", err)
	}
	if result.FileBytes > result.MaxBytes {
		t.Fatalf("dropped file bytes = %d, want <= %d", result.FileBytes, result.MaxBytes)
	}
	if result.Total == 0 {
		t.Fatalf("dropped limited total = 0, want newest records kept")
	}
	if got := result.Items[0].Connection.ID; got != "limited-39" {
		t.Fatalf("newest kept dropped = %q, want limited-39", got)
	}
	if result.Total >= 40 {
		t.Fatalf("dropped total = %d, want old records compacted", result.Total)
	}
}
