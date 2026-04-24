//go:build windows

package win

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

type tcp4ExactKey struct {
	LocalAddr  uint32
	LocalPort  uint16
	RemoteAddr uint32
	RemotePort uint16
}

type tcp4LocalKey struct {
	LocalAddr uint32
	LocalPort uint16
}

type tcp6ExactKey struct {
	LocalAddr  [16]byte
	LocalPort  uint16
	RemoteAddr [16]byte
	RemotePort uint16
}

type tcp6LocalKey struct {
	LocalAddr [16]byte
	LocalPort uint16
}

type exeCacheEntry struct {
	Path    string
	Expires time.Time
}

type OwnerCache struct {
	mu          sync.RWMutex
	refreshMu   sync.Mutex
	interval    time.Duration
	lastRefresh time.Time
	v4Exact     map[tcp4ExactKey]uint32
	v4Local     map[tcp4LocalKey]uint32
	v6Exact     map[tcp6ExactKey]uint32
	v6Local     map[tcp6LocalKey]uint32
	exeByPID    map[uint32]exeCacheEntry
}

const exeCacheTTL = 5 * time.Minute

func NewOwnerCache(interval time.Duration) *OwnerCache {
	if interval < 50*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	return &OwnerCache{
		interval: interval,
		v4Exact:  map[tcp4ExactKey]uint32{},
		v4Local:  map[tcp4LocalKey]uint32{},
		v6Exact:  map[tcp6ExactKey]uint32{},
		v6Local:  map[tcp6LocalKey]uint32{},
		exeByPID: map[uint32]exeCacheEntry{},
	}
}

func (c *OwnerCache) Start(ctx context.Context) {
	_ = c.ForceRefresh()
	go func() {
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = c.ForceRefresh()
			}
		}
	}()
}

func (c *OwnerCache) Lookup(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (uint32, string, bool) {
	srcIP = srcIP.Unmap()
	dstIP = dstIP.Unmap()
	c.mu.RLock()
	var pid uint32
	if srcIP.Is4() && dstIP.Is4() {
		s := srcIP.As4()
		d := dstIP.As4()
		pid = c.v4Exact[tcp4ExactKey{LocalAddr: binary.LittleEndian.Uint32(s[:]), LocalPort: srcPort, RemoteAddr: binary.LittleEndian.Uint32(d[:]), RemotePort: dstPort}]
		if pid == 0 {
			pid = c.v4Local[tcp4LocalKey{LocalAddr: binary.LittleEndian.Uint32(s[:]), LocalPort: srcPort}]
		}
	} else if srcIP.Is6() && dstIP.Is6() {
		pid = c.v6Exact[tcp6ExactKey{LocalAddr: srcIP.As16(), LocalPort: srcPort, RemoteAddr: dstIP.As16(), RemotePort: dstPort}]
		if pid == 0 {
			pid = c.v6Local[tcp6LocalKey{LocalAddr: srcIP.As16(), LocalPort: srcPort}]
		}
	}
	entry := c.exeByPID[pid]
	c.mu.RUnlock()
	if pid == 0 {
		return 0, "", false
	}
	if entry.Path != "" && time.Now().UTC().Before(entry.Expires) {
		return pid, entry.Path, true
	}
	path, _ := ExePath(pid)
	c.mu.Lock()
	c.exeByPID[pid] = exeCacheEntry{Path: path, Expires: time.Now().UTC().Add(exeCacheTTL)}
	c.mu.Unlock()
	return pid, path, true
}

func (c *OwnerCache) ForceRefresh() error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	v4Exact := map[tcp4ExactKey]uint32{}
	v4Local := map[tcp4LocalKey]uint32{}
	v6Exact := map[tcp6ExactKey]uint32{}
	v6Local := map[tcp6LocalKey]uint32{}

	if rows, err := loadTCP4Table(tcpTableOwnerPIDAll); err == nil {
		for _, row := range rows {
			lp := decodePort(row.LocalPort)
			if lp == 0 || row.OwningPID == 0 {
				continue
			}
			lk := tcp4LocalKey{LocalAddr: row.LocalAddr, LocalPort: lp}
			if _, ok := v4Local[lk]; !ok {
				v4Local[lk] = row.OwningPID
			}
			rp := decodePort(row.RemotePort)
			if row.RemoteAddr != 0 && rp != 0 {
				v4Exact[tcp4ExactKey{LocalAddr: row.LocalAddr, LocalPort: lp, RemoteAddr: row.RemoteAddr, RemotePort: rp}] = row.OwningPID
			}
		}
	}
	if rows, err := loadTCP6Table(tcpTableOwnerPIDAll); err == nil {
		for _, row := range rows {
			lp := decodePort(row.LocalPort)
			if lp == 0 || row.OwningPID == 0 {
				continue
			}
			lk := tcp6LocalKey{LocalAddr: row.LocalAddr, LocalPort: lp}
			if _, ok := v6Local[lk]; !ok {
				v6Local[lk] = row.OwningPID
			}
			rp := decodePort(row.RemotePort)
			if row.RemotePort != 0 && rp != 0 {
				v6Exact[tcp6ExactKey{LocalAddr: row.LocalAddr, LocalPort: lp, RemoteAddr: row.RemoteAddr, RemotePort: rp}] = row.OwningPID
			}
		}
	}
	c.mu.Lock()
	c.v4Exact = v4Exact
	c.v4Local = v4Local
	c.v6Exact = v6Exact
	c.v6Local = v6Local
	now := time.Now().UTC()
	c.exeByPID = compactExeCache(c.exeByPID, now)
	c.lastRefresh = now
	c.mu.Unlock()
	return nil
}

func compactExeCache(cache map[uint32]exeCacheEntry, now time.Time) map[uint32]exeCacheEntry {
	if len(cache) == 0 {
		return map[uint32]exeCacheEntry{}
	}
	next := map[uint32]exeCacheEntry{}
	for pid, entry := range cache {
		if now.Before(entry.Expires) {
			next[pid] = entry
		}
	}
	return next
}
