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

func TestFlowTableCleanupKeepsAcceptedFlows(t *testing.T) {
	table := NewFlowTable()
	flow := Flow{
		ClientIP:     netip.MustParseAddr("127.0.0.1"),
		ClientPort:   41000,
		OriginalIP:   netip.MustParseAddr("1.1.1.1"),
		OriginalPort: 443,
		LastSeen:     time.Now().UTC().Add(-10 * time.Minute),
	}
	table.flows[makeFlowKey(flow.ClientIP, flow.ClientPort)] = flow

	accepted, ok := table.MarkAccepted(flow.ClientIP, flow.ClientPort)
	if !ok {
		t.Fatal("MarkAccepted returned ok=false")
	}
	if !accepted.Accepted {
		t.Fatal("accepted flow should be marked accepted")
	}
	accepted.LastSeen = time.Now().UTC().Add(-10 * time.Minute)
	table.flows[makeFlowKey(flow.ClientIP, flow.ClientPort)] = accepted
	table.Cleanup(time.Minute)

	if got := len(table.flows); got != 1 {
		t.Fatalf("flow table len = %d, want accepted flow retained", got)
	}
	table.Delete(flow.ClientIP, flow.ClientPort)
	if got := len(table.flows); got != 0 {
		t.Fatalf("flow table len after delete = %d, want 0", got)
	}
}

func TestFlowTableRedirectPacket(t *testing.T) {
	table := NewFlowTable()
	clientIP := netip.MustParseAddr("192.0.2.10")
	originalIP := netip.MustParseAddr("198.51.100.20")
	table.Register(Flow{
		ClientIP:     clientIP,
		ClientPort:   41000,
		OriginalIP:   originalIP,
		OriginalPort: 443,
	})

	flow, direction, ok := table.RedirectPacket(clientIP, 41000, originalIP, 443, 39080)
	if !ok || direction != RedirectAppToListener {
		t.Fatalf("app packet redirect = flow:%+v direction:%d ok:%v, want app-to-listener", flow, direction, ok)
	}
	if flow.OriginalIP != originalIP || flow.OriginalPort != 443 {
		t.Fatalf("unexpected app redirect flow: %+v", flow)
	}

	flow, direction, ok = table.RedirectPacket(clientIP, 39080, clientIP, 41000, 39080)
	if !ok || direction != RedirectListenerToApp {
		t.Fatalf("listener packet redirect = flow:%+v direction:%d ok:%v, want listener-to-app", flow, direction, ok)
	}

	if _, _, ok = table.RedirectPacket(clientIP, 41001, originalIP, 443, 39080); ok {
		t.Fatal("untracked packet should not redirect")
	}
}

func TestFlowTableChurnReturnsToEmptyAndCompacts(t *testing.T) {
	table := NewFlowTable()
	clientIP := netip.MustParseAddr("127.0.0.1")
	originalIP := netip.MustParseAddr("1.1.1.1")
	for i := 0; i < 5000; i++ {
		flow := Flow{
			ClientIP:     clientIP,
			ClientPort:   uint16(20000 + i%30000),
			OriginalIP:   originalIP,
			OriginalPort: 443,
		}
		table.Register(flow)
		if _, ok := table.MarkAccepted(flow.ClientIP, flow.ClientPort); !ok {
			t.Fatalf("MarkAccepted failed for flow %d", i)
		}
		table.Delete(flow.ClientIP, flow.ClientPort)
	}
	if got := table.Len(); got != 0 {
		t.Fatalf("flow table len = %d, want 0", got)
	}
	if table.deletes != 0 {
		t.Fatalf("delete counter = %d, want reset after empty compaction", table.deletes)
	}
}

func TestFlowTableHighWaterChurnReleasesAndSignalsOnce(t *testing.T) {
	table := NewFlowTable()
	clientIP := netip.MustParseAddr("127.0.0.1")
	originalIP := netip.MustParseAddr("1.1.1.1")
	emptySignals := 0
	table.SetOnEmpty(func() { emptySignals++ })

	const count = 512
	for i := 0; i < count; i++ {
		table.Register(Flow{
			ClientIP:     clientIP,
			ClientPort:   uint16(20000 + i),
			OriginalIP:   originalIP,
			OriginalPort: 443,
		})
	}
	for i := 0; i < count; i++ {
		table.Delete(clientIP, uint16(20000+i))
	}

	if got := table.Len(); got != 0 {
		t.Fatalf("flow table len = %d, want 0", got)
	}
	if emptySignals != 1 {
		t.Fatalf("empty signals = %d, want 1", emptySignals)
	}
	if table.peak != 0 || table.deletes != 0 {
		t.Fatalf("high-water bookkeeping was not reset: peak=%d deletes=%d", table.peak, table.deletes)
	}
}

func TestFlowTableSteadyChurnDoesNotRebuildLiveSet(t *testing.T) {
	table := benchmarkFlowTable(1024)
	flow, _ := table.Lookup(netip.MustParseAddr("192.0.2.10"), 40000)
	flow.ClientPort = 60000
	// A steady stream of short connections alongside long-lived ones should
	// reuse the table without allocating maps proportional to the live set.
	allocs := testing.AllocsPerRun(256, func() {
		table.Register(flow)
		table.Delete(flow.ClientIP, flow.ClientPort)
	})
	if allocs > 1 {
		t.Fatalf("steady connection churn allocates %.1f times per connection", allocs)
	}
	for port := uint16(40000); port < 41023; port++ {
		table.Delete(flow.ClientIP, port)
	}
	if table.Len() != 1 || table.peak > flowMapCompactDeletes {
		t.Fatalf("burst did not compact around surviving flow: len=%d peak=%d", table.Len(), table.peak)
	}
}

func BenchmarkFlowTableRedirectPacketUntracked(b *testing.B) {
	table := benchmarkFlowTable(1024)
	src := netip.MustParseAddr("203.0.113.10")
	dst := netip.MustParseAddr("203.0.113.20")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = table.RedirectPacket(src, uint16(30000+i%1000), dst, 443, 39080)
	}
}

func BenchmarkFlowTableRedirectPacketTrackedApp(b *testing.B) {
	table := benchmarkFlowTable(1024)
	client := netip.MustParseAddr("192.0.2.10")
	original := netip.MustParseAddr("198.51.100.20")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		port := uint16(40000 + i%1024)
		_, _, _ = table.RedirectPacket(client, port, original, 443, 39080)
	}
}

func BenchmarkFlowTableRegisterDeleteChurn(b *testing.B) {
	client := netip.MustParseAddr("192.0.2.10")
	original := netip.MustParseAddr("198.51.100.20")
	table := NewFlowTable()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		port := uint16(20000 + i%30000)
		table.Register(Flow{ClientIP: client, ClientPort: port, OriginalIP: original, OriginalPort: 443})
		table.Delete(client, port)
	}
}

func benchmarkFlowTable(size int) *FlowTable {
	table := NewFlowTable()
	client := netip.MustParseAddr("192.0.2.10")
	original := netip.MustParseAddr("198.51.100.20")
	for i := 0; i < size; i++ {
		table.Register(Flow{
			ClientIP:     client,
			ClientPort:   uint16(40000 + i),
			OriginalIP:   original,
			OriginalPort: 443,
		})
	}
	return table
}
