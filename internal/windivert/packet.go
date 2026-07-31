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
		if len(raw) < 40 {
			return Packet{}, errors.New("not ipv6 tcp")
		}
		off, err := ipv6TCPHeaderOffset(raw)
		if err != nil {
			return Packet{}, err
		}
		src, _ := netip.AddrFromSlice(raw[8:24])
		dst, _ := netip.AddrFromSlice(raw[24:40])
		flags := raw[off+13]
		return Packet{Raw: raw, IPv6: true, tcpOff: off, Src: src, Dst: dst, SrcPort: binary.BigEndian.Uint16(raw[off : off+2]), DstPort: binary.BigEndian.Uint16(raw[off+2 : off+4]), SYN: flags&0x02 != 0, ACK: flags&0x10 != 0, RST: flags&0x04 != 0, FIN: flags&0x01 != 0}, nil
	default:
		return Packet{}, errors.New("unknown ip version")
	}
}

func ipv6TCPHeaderOffset(raw []byte) (int, error) {
	if len(raw) < 40 {
		return 0, errors.New("ipv6 packet too small")
	}
	next := raw[6]
	off := 40
	for extensions := 0; extensions <= 8; extensions++ {
		switch next {
		case 6:
			if len(raw) < off+20 {
				return 0, errors.New("truncated ipv6 tcp header")
			}
			return off, nil
		case 0, 43, 60, 135:
			if len(raw) < off+2 {
				return 0, errors.New("truncated ipv6 extension header")
			}
			headerLen := (int(raw[off+1]) + 1) * 8
			if headerLen < 8 || len(raw) < off+headerLen {
				return 0, errors.New("invalid ipv6 extension header length")
			}
			next = raw[off]
			off += headerLen
		case 44:
			if len(raw) < off+8 {
				return 0, errors.New("truncated ipv6 fragment header")
			}
			fragment := binary.BigEndian.Uint16(raw[off+2 : off+4])
			if fragment&0xfff8 != 0 {
				return 0, errors.New("non-initial ipv6 fragment")
			}
			next = raw[off]
			off += 8
		case 51:
			if len(raw) < off+2 {
				return 0, errors.New("truncated ipv6 authentication header")
			}
			headerLen := (int(raw[off+1]) + 2) * 4
			if headerLen < 8 || len(raw) < off+headerLen {
				return 0, errors.New("invalid ipv6 authentication header length")
			}
			next = raw[off]
			off += headerLen
		default:
			return 0, errors.New("ipv6 packet does not contain tcp")
		}
	}
	return 0, errors.New("too many ipv6 extension headers")
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
