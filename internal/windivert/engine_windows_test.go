//go:build windows

package windivert

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/proxy"
)

type delayedOwnerCache struct {
	refreshes  int
	foundAfter int
	onRefresh  func()
}

func (*delayedOwnerCache) RefreshIfStale(time.Duration) error { return nil }
func (c *delayedOwnerCache) ForceRefresh() error {
	c.refreshes++
	if c.onRefresh != nil {
		c.onRefresh()
	}
	return nil
}
func (c *delayedOwnerCache) Lookup(netip.Addr, uint16, netip.Addr, uint16) (uint32, string, bool) {
	if c.refreshes >= c.foundAfter {
		return 42, `C:\late.exe`, true
	}
	return 0, "", false
}

func TestOwnerLookupRefreshesDelayedRows(t *testing.T) {
	owners := &delayedOwnerCache{foundAfter: 2}
	engine := &Engine{owners: owners}
	pid, exe, tries, ok := engine.lookup(context.Background(), Packet{})
	if !ok || pid != 42 || exe != `C:\late.exe` || tries != 3 {
		t.Fatalf("late owner lookup = pid=%d exe=%q tries=%d ok=%v", pid, exe, tries, ok)
	}
}

func TestOwnerLookupRetryStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owners := &delayedOwnerCache{foundAfter: 100, onRefresh: cancel}
	engine := &Engine{owners: owners}
	_, _, tries, ok := engine.lookup(ctx, Packet{})
	if ok || tries != 2 || owners.refreshes != 1 {
		t.Fatalf("canceled lookup continued: tries=%d refreshes=%d ok=%v", tries, owners.refreshes, ok)
	}
}

func TestSharedRedirectorRewritesAppAndListenerPackets(t *testing.T) {
	clientIP := netip.MustParseAddr("192.0.2.10")
	originalIP := netip.MustParseAddr("198.51.100.20")
	table := proxy.NewFlowTable()
	table.Register(proxy.Flow{
		ClientIP:     clientIP,
		ClientPort:   41000,
		OriginalIP:   originalIP,
		OriginalPort: 443,
	})
	engine := &Engine{ListenerPort: 39080, Flows: table}

	appPkt := mustParseTestPacket(t, testIPv4TCP(clientIP, 41000, originalIP, 443))
	if !engine.rewriteRedirectPacket(&appPkt) {
		t.Fatal("app packet was not rewritten")
	}
	if appPkt.Dst != clientIP || appPkt.DstPort != 39080 {
		t.Fatalf("app packet dst = %s:%d, want %s:%d", appPkt.Dst, appPkt.DstPort, clientIP, 39080)
	}

	listenerPkt := mustParseTestPacket(t, testIPv4TCP(clientIP, 39080, clientIP, 41000))
	if !engine.rewriteRedirectPacket(&listenerPkt) {
		t.Fatal("listener packet was not rewritten")
	}
	if listenerPkt.Src != originalIP || listenerPkt.SrcPort != 443 {
		t.Fatalf("listener packet src = %s:%d, want %s:%d", listenerPkt.Src, listenerPkt.SrcPort, originalIP, 443)
	}
}

func TestSharedRedirectorLeavesUntrackedPacketsAlone(t *testing.T) {
	engine := &Engine{ListenerPort: 39080, Flows: proxy.NewFlowTable()}
	pkt := mustParseTestPacket(t, testIPv4TCP(
		netip.MustParseAddr("192.0.2.10"),
		41000,
		netip.MustParseAddr("203.0.113.30"),
		443,
	))

	if engine.rewriteRedirectPacket(&pkt) {
		t.Fatal("untracked packet should not be rewritten")
	}
	if pkt.DstPort != 443 {
		t.Fatalf("untracked packet dst port = %d, want 443", pkt.DstPort)
	}
}

func TestBuildRedirectorFilterIsSharedAndBounded(t *testing.T) {
	filter := buildRedirectorFilter(39080)
	want := "outbound and tcp and !impostor and (!loopback or tcp.SrcPort == 39080 or tcp.DstPort == 39080)"
	if filter != want {
		t.Fatalf("filter = %q, want %q", filter, want)
	}
}

func mustParseTestPacket(t *testing.T, raw []byte) Packet {
	t.Helper()
	pkt, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	return pkt
}

func testIPv4TCP(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16) []byte {
	raw := make([]byte, 40)
	raw[0] = 0x45
	raw[9] = 6
	src4 := src.As4()
	dst4 := dst.As4()
	copy(raw[12:16], src4[:])
	copy(raw[16:20], dst4[:])
	binary.BigEndian.PutUint16(raw[20:22], srcPort)
	binary.BigEndian.PutUint16(raw[22:24], dstPort)
	raw[33] = 0x10
	return raw
}
