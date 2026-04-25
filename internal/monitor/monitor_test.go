package monitor

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/openai/pitchprox/internal/config"
)

func TestSnapshotTrafficBucketSeconds(t *testing.T) {
	tests := []struct {
		name      string
		retention time.Duration
		want      int
	}{
		{name: "short window stays per-second", retention: 7 * time.Minute, want: 4},
		{name: "one hour window buckets", retention: time.Hour, want: 30},
		{name: "day window stays bounded", retention: 24 * time.Hour, want: 720},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := snapshotTrafficBucketSeconds(tt.retention); got != tt.want {
				t.Fatalf("snapshotTrafficBucketSeconds(%v) = %d, want %d", tt.retention, got, tt.want)
			}
		})
	}
}

func TestOpeningConnectionsExpire(t *testing.T) {
	now := time.Now().UTC()
	conn := Connection{
		ID:            "opening",
		State:         "opening",
		CreatedAt:     now.Add(-openingMaxAge - time.Second),
		LastUpdatedAt: now.Add(-openingMaxAge - time.Second),
	}
	if !shouldExpireConnection(now, conn, 24*time.Hour) {
		t.Fatal("stale opening connection did not expire")
	}

	conn.State = "open"
	if shouldExpireConnection(now, conn, time.Minute) {
		t.Fatal("open connection expired unexpectedly")
	}
}

func TestActiveMapCompactsAfterDeletes(t *testing.T) {
	b := &Bus{
		active:          map[string]Connection{},
		trafficLive:     map[int64]TrafficSample{},
		retentionWindow: defaultRetention,
	}
	for i := 0; i < 32; i++ {
		id := string(rune('a' + i))
		b.active[id] = Connection{ID: id, State: "closed", LastUpdatedAt: time.Now().UTC()}
	}
	for id := range b.active {
		b.deleteActiveLocked(id)
	}
	if len(b.active) != 0 {
		t.Fatalf("active len = %d, want 0", len(b.active))
	}
	if b.activeDeletes != 0 {
		t.Fatalf("activeDeletes = %d, want reset after compaction", b.activeDeletes)
	}
	if b.active == nil {
		t.Fatal("active map should be reset to an empty map, not nil")
	}
}

func TestSnapshotIncludesNewConnections(t *testing.T) {
	b, err := NewBus(filepath.Join(t.TempDir(), "pitchProx.history"))
	if err != nil {
		t.Fatalf("new bus: %v", err)
	}
	defer func() {
		if err := b.Close(); err != nil {
			t.Fatalf("close bus: %v", err)
		}
	}()

	now := time.Now().UTC().Truncate(time.Second)
	exe := `C:\Apps\demo.exe`
	b.UpsertConnection(Connection{
		ID:            "history-same",
		PID:           101,
		ExePath:       exe,
		OriginalIP:    "198.51.100.10",
		OriginalPort:  443,
		Action:        config.ActionDirect,
		State:         "closed",
		CreatedAt:     now.Add(-2 * time.Minute),
		LastUpdatedAt: now.Add(-2 * time.Minute),
		Count:         1,
	})
	b.UpsertConnection(Connection{
		ID:            "live-suppressed",
		PID:           202,
		ExePath:       exe,
		OriginalIP:    "198.51.100.10",
		OriginalPort:  443,
		Action:        config.ActionDirect,
		State:         "open",
		CreatedAt:     now,
		LastUpdatedAt: now,
		Count:         1,
	})
	b.UpsertConnection(Connection{
		ID:            "live-new",
		PID:           202,
		ExePath:       exe,
		OriginalIP:    "203.0.113.40",
		OriginalPort:  443,
		Action:        config.ActionDirect,
		State:         "open",
		CreatedAt:     now,
		LastUpdatedAt: now,
		Count:         1,
	})

	snap := b.SnapshotWithOptions(SnapshotOptions{IncludeLogs: false})
	if snap.NewBaselineMinutes != 7 {
		t.Fatalf("new baseline minutes = %d, want 7", snap.NewBaselineMinutes)
	}
	if snap.NewRecentMinutes != 1 {
		t.Fatalf("new recent minutes = %d, want 1", snap.NewRecentMinutes)
	}
	if len(snap.NewConnections) != 1 {
		t.Fatalf("new connections len = %d, want 1: %+v", len(snap.NewConnections), snap.NewConnections)
	}
	if snap.NewConnections[0].OriginalIP != "203.0.113.40" {
		t.Fatalf("new connection ip = %s, want 203.0.113.40", snap.NewConnections[0].OriginalIP)
	}
}
