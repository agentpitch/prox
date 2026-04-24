//go:build windows

package win

import (
	"encoding/binary"
	"net/netip"
	"sync"
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

type TCPSnapshotter struct {
	mu       sync.Mutex
	exeByPID map[uint32]exeCacheEntry
}

var defaultTCPSnapshotter = NewTCPSnapshotter()

func ListTCPConnections() ([]TCPConnection, error) {
	return defaultTCPSnapshotter.ListTCPConnections()
}

func NewTCPSnapshotter() *TCPSnapshotter {
	return &TCPSnapshotter{exeByPID: map[uint32]exeCacheEntry{}}
}

func (s *TCPSnapshotter) ListTCPConnections() ([]TCPConnection, error) {
	if s == nil {
		s = defaultTCPSnapshotter
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.exeByPID = compactExeCache(s.exeByPID, now)
	s.mu.Unlock()
	items := make([]TCPConnection, 0, 128)

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
				ExePath:    s.exePathCached(row.OwningPID, now),
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
				ExePath:    s.exePathCached(row.OwningPID, now),
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

func (s *TCPSnapshotter) exePathCached(pid uint32, now time.Time) string {
	if s == nil {
		path, _ := ExePath(pid)
		return path
	}
	s.mu.Lock()
	entry, ok := s.exeByPID[pid]
	if ok && now.Before(entry.Expires) {
		path := entry.Path
		s.mu.Unlock()
		return path
	}
	s.mu.Unlock()

	path, _ := ExePath(pid)

	s.mu.Lock()
	if s.exeByPID == nil {
		s.exeByPID = map[uint32]exeCacheEntry{}
	}
	s.exeByPID[pid] = exeCacheEntry{Path: path, Expires: now.Add(exeCacheTTL)}
	s.mu.Unlock()
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
