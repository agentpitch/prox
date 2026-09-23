package monitor

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
)

func BenchmarkActiveConnectionChurn(b *testing.B) {
	bus := &Bus{active: make(map[string]Connection, 4096)}
	ids := make([]string, 4096)
	for i := range ids {
		ids[i] = fmt.Sprintf("connection-%d", i)
		bus.active[ids[i]] = Connection{ID: ids[i], State: "open"}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := ids[i%len(ids)]
		bus.deleteActiveLocked(id)
		bus.active[id] = Connection{ID: id, State: "open"}
	}
}

func BenchmarkPublishTransientEventWithoutSubscribers(b *testing.B) {
	bus := &Bus{}
	payload := strings.Repeat("state", 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.PublishTransientEvent("state", payload)
	}
}

type observedJSONPayload struct{ calls *int }

func (p observedJSONPayload) MarshalJSON() ([]byte, error) {
	(*p.calls)++
	return []byte(`{"ready":true}`), nil
}

func TestTransientEventsOnlyEncodeForSubscribers(t *testing.T) {
	bus := &Bus{subs: make(map[int]chan []byte)}
	encodes := 0
	payload := observedJSONPayload{calls: &encodes}
	bus.PublishTransientEvent("state", payload)
	if encodes != 0 {
		t.Fatalf("background event encoded %d times without subscribers", encodes)
	}
	_, events, cancel := bus.Subscribe()
	bus.PublishTransientEvent("state", payload)
	select {
	case event := <-events:
		if string(event) != `{"type":"state","data":{"ready":true}}` {
			t.Fatalf("subscriber received %s", event)
		}
	default:
		t.Fatal("subscriber did not receive the event")
	}
	cancel()
	bus.PublishTransientEvent("state", payload)
	if encodes != 1 {
		t.Fatalf("encoded %d events, want only the one with a subscriber", encodes)
	}
}

func TestBackgroundWarningStillPersistsWithoutSubscribers(t *testing.T) {
	bus, err := NewBus(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bus.Close() })
	bus.AddLog("warn", "background warning")
	logs := bus.Snapshot().Logs
	if len(logs) != 1 || logs[0].Message != "background warning" {
		t.Fatalf("persisted warning = %+v", logs)
	}
}

func TestActiveMapCompactionIsProportionalToDrainage(t *testing.T) {
	bus := &Bus{active: make(map[string]Connection, 8192)}
	for i := 0; i < 8192; i++ {
		id := fmt.Sprintf("connection-%d", i)
		bus.active[id] = Connection{ID: id, State: "open"}
	}
	compactions := 0
	for i := 1; i < 8192; i++ {
		bus.deleteActiveLocked(fmt.Sprintf("connection-%d", i))
		if bus.activeDeletes == 0 {
			compactions++
		}
	}
	if compactions == 0 || compactions > 6 {
		t.Fatalf("compacted %d times draining 8192 connections, want geometric shrink", compactions)
	}
	if len(bus.active) != 1 || bus.active["connection-0"].ID != "connection-0" {
		t.Fatalf("long-lived survivor lost: %+v", bus.active)
	}
}

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

func TestDetailedRuleConnectionDoesNotDoubleCountRuleStats(t *testing.T) {
	b, err := NewBus(filepath.Join(t.TempDir(), "pitchProx.history"))
	if err != nil {
		t.Fatalf("new bus: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	b.AddRuleConditionConnection("rule", "Rule", config.ActionProxy, RuleConditionMatch{
		Application: "browser.exe",
		Host:        "*.example.com",
		Port:        "443",
		Source:      RuleConditionSourceIntercepted,
	})
	b.AddRuleTraffic("rule", "Rule", config.ActionProxy, 100, 200)

	detail, err := b.RuleConditionActivity("rule", time.Minute, 20)
	if err != nil {
		t.Fatalf("condition activity: %v", err)
	}
	if detail.TotalHits != 1 || len(detail.Conditions) != 1 || detail.Conditions[0].Hits != 1 {
		t.Fatalf("condition detail = %+v", detail)
	}
	snapshot := b.SnapshotWithOptions(SnapshotOptions{IncludeLogs: false})
	if len(snapshot.RuleStats) != 1 || snapshot.RuleStats[0].Connections != 1 {
		t.Fatalf("rule stats = %+v, want one connection", snapshot.RuleStats)
	}
	if snapshot.RuleStats[0].UpBytes != 100 || snapshot.RuleStats[0].DownBytes != 200 {
		t.Fatalf("rule traffic = %+v", snapshot.RuleStats[0])
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
