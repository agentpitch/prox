package proxy

import (
	"net/netip"
	"testing"
	"time"
)

func TestFlowTableCleanupCompactsWhenEmpty(t *testing.T) {
	table := NewFlowTable()
	now := time.Now().UTC()
	for i := 0; i < 64; i++ {
		flow := Flow{
			ClientIP:     netip.MustParseAddr("127.0.0.1"),
			ClientPort:   uint16(40000 + i),
			OriginalIP:   netip.MustParseAddr("1.1.1.1"),
			OriginalPort: 443,
			LastSeen:     now.Add(-10 * time.Minute),
		}
		table.flows[makeFlowKey(flow.ClientIP, flow.ClientPort)] = flow
	}

	table.Cleanup(time.Minute)

	if got := len(table.flows); got != 0 {
		t.Fatalf("flow table len = %d, want 0", got)
	}
	if table.deletes != 0 {
		t.Fatalf("flow table deletes = %d, want reset after compaction", table.deletes)
	}
	if table.flows == nil {
		t.Fatal("flow map should be reset to an empty map, not nil")
	}
}
