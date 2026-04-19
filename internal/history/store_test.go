package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/openai/pitchprox/internal/config"
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

	base := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Minute)
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
