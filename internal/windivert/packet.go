package windivert

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

type Packet struct {
	Raw     []byte
	IPv6    bool
	tcpOff  int
	Src     netip.Addr
	Dst     netip.Addr
	SrcPort uint16
	DstPort uint16
	SYN     bool
	ACK     bool
	RST     bool
	FIN     bool
}

func ParsePacket(raw []byte) (Packet, error) {
	if len(raw) < 20 {
		return Packet{}, errors.New("packet too small")
	}
	ver := raw[0] >> 4
	switch ver {
	case 4:
		ihl := int(raw[0]&0x0f) * 4
		if len(raw) < ihl+20 || ihl < 20 || raw[9] != 6 {
			return Packet{}, errors.New("not ipv4 tcp")
		}
		src, _ := netip.AddrFromSlice(raw[12:16])
		dst, _ := netip.AddrFromSlice(raw[16:20])
		off := ihl
		flags := raw[off+13]
		return Packet{Raw: raw, tcpOff: off, Src: src.Unmap(), Dst: dst.Unmap(), SrcPort: binary.BigEndian.Uint16(raw[off : off+2]), DstPort: binary.BigEndian.Uint16(raw[off+2 : off+4]), SYN: flags&0x02 != 0, ACK: flags&0x10 != 0, RST: flags&0x04 != 0, FIN: flags&0x01 != 0}, nil
	case 6:
		if len(raw) < 60 || raw[6] != 6 {
			return Packet{}, errors.New("not ipv6 tcp")
		}
		src, _ := netip.AddrFromSlice(raw[8:24])
		dst, _ := netip.AddrFromSlice(raw[24:40])
		off := 40
		flags := raw[off+13]
		return Packet{Raw: raw, IPv6: true, tcpOff: off, Src: src, Dst: dst, SrcPort: binary.BigEndian.Uint16(raw[off : off+2]), DstPort: binary.BigEndian.Uint16(raw[off+2 : off+4]), SYN: flags&0x02 != 0, ACK: flags&0x10 != 0, RST: flags&0x04 != 0, FIN: flags&0x01 != 0}, nil
	default:
		return Packet{}, errors.New("unknown ip version")
	}
}

func (p *Packet) SetDst(addr netip.Addr, port uint16) {
	if p.IPv6 {
		a := addr.As16()
		copy(p.Raw[24:40], a[:])
	} else {
		a := addr.As4()
		copy(p.Raw[16:20], a[:])
	}
	binary.BigEndian.PutUint16(p.Raw[p.tcpOff+2:p.tcpOff+4], port)
	p.Dst, p.DstPort = addr, port
}

func (p *Packet) SetSrc(addr netip.Addr, port uint16) {
	if p.IPv6 {
		a := addr.As16()
		copy(p.Raw[8:24], a[:])
	} else {
		a := addr.As4()
		copy(p.Raw[12:16], a[:])
	}
	binary.BigEndian.PutUint16(p.Raw[p.tcpOff:p.tcpOff+2], port)
	p.Src, p.SrcPort = addr, port
}
