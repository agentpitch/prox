//go:build windows

package win

import (
	"encoding/binary"
	"net/netip"
	"time"
)

type TCPConnection struct {
	PID        uint32
	ExePath    string
	LocalIP    netip.Addr
	LocalPort  uint16
	RemoteIP   netip.Addr
	RemotePort uint16
	State      uint32
	IPv6       bool
	SeenAt     time.Time
}

const tcpStateListen = 2

func ListTCPConnections() ([]TCPConnection, error) {
	now := time.Now().UTC()
	items := make([]TCPConnection, 0, 128)
	exeCache := map[uint32]string{}

	if rows, err := loadTCP4Table(tcpTableOwnerPIDAll); err == nil {
		for _, row := range rows {
			lp := decodePort(row.LocalPort)
			rp := decodePort(row.RemotePort)
			if row.OwningPID == 0 || lp == 0 || rp == 0 || row.State == tcpStateListen || row.RemoteAddr == 0 {
				continue
			}
			local := v4Addr(row.LocalAddr)
			remote := v4Addr(row.RemoteAddr)
			if !local.IsValid() || !remote.IsValid() {
				continue
			}
			items = append(items, TCPConnection{
				PID:        row.OwningPID,
				ExePath:    exePathCached(exeCache, row.OwningPID),
				LocalIP:    local,
				LocalPort:  lp,
				RemoteIP:   remote,
				RemotePort: rp,
				State:      row.State,
				SeenAt:     now,
			})
		}
	}
	if rows, err := loadTCP6Table(tcpTableOwnerPIDAll); err == nil {
		for _, row := range rows {
			lp := decodePort(row.LocalPort)
			rp := decodePort(row.RemotePort)
			if row.OwningPID == 0 || lp == 0 || rp == 0 || row.State == tcpStateListen || isZero16(row.RemoteAddr) {
				continue
			}
			local := netip.AddrFrom16(row.LocalAddr).Unmap()
			remote := netip.AddrFrom16(row.RemoteAddr).Unmap()
			if !local.IsValid() || !remote.IsValid() {
				continue
			}
			items = append(items, TCPConnection{
				PID:        row.OwningPID,
				ExePath:    exePathCached(exeCache, row.OwningPID),
				LocalIP:    local,
				LocalPort:  lp,
				RemoteIP:   remote,
				RemotePort: rp,
				State:      row.State,
				IPv6:       true,
				SeenAt:     now,
			})
		}
	}
	return items, nil
}

func exePathCached(cache map[uint32]string, pid uint32) string {
	if path, ok := cache[pid]; ok {
		return path
	}
	path, _ := ExePath(pid)
	cache[pid] = path
	return path
}

func v4Addr(u uint32) netip.Addr {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], u)
	return netip.AddrFrom4(b)
}

func isZero16(v [16]byte) bool {
	for _, b := range v {
		if b != 0 {
			return false
		}
	}
	return true
}
