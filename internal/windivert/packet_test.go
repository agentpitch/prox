package windivert

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParsePacketIPv6ExtensionChain(t *testing.T) {
	raw := make([]byte, 40+8+8+20)
	raw[0] = 0x60
	raw[6] = 0 // Hop-by-Hop.
	raw[40] = 60
	raw[41] = 0
	raw[48] = 6
	raw[49] = 0
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	copy(raw[8:24], src[:])
	copy(raw[24:40], dst[:])
	tcp := 56
	binary.BigEndian.PutUint16(raw[tcp:tcp+2], 40123)
	binary.BigEndian.PutUint16(raw[tcp+2:tcp+4], 443)
	raw[tcp+13] = 0x02

	pkt, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if !pkt.IPv6 || pkt.SrcPort != 40123 || pkt.DstPort != 443 || !pkt.SYN {
		t.Fatalf("unexpected packet: %+v", pkt)
	}
}

func TestParsePacketRejectsNonInitialIPv6Fragment(t *testing.T) {
	raw := make([]byte, 40+8+20)
	raw[0] = 0x60
	raw[6] = 44
	raw[40] = 6
	binary.BigEndian.PutUint16(raw[42:44], 8)
	if _, err := ParsePacket(raw); err == nil {
		t.Fatal("ParsePacket accepted non-initial IPv6 fragment")
	}
}
