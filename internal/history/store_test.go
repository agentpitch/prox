package history

import (
	"fmt"
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
