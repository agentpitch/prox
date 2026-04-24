//go:build windows

package win

import (
	"testing"
	"time"
)

func TestCompactExeCacheDropsExpiredEntries(t *testing.T) {
	now := time.Now().UTC()
	cache := map[uint32]exeCacheEntry{
		10: {Path: `C:\old.exe`, Expires: now.Add(-time.Second)},
		20: {Path: `C:\new.exe`, Expires: now.Add(time.Minute)},
	}

	got := compactExeCache(cache, now)

	if _, ok := got[10]; ok {
		t.Fatal("expired PID cache entry was retained")
	}
	if item, ok := got[20]; !ok || item.Path != `C:\new.exe` {
		t.Fatalf("fresh PID cache entry missing or changed: %+v", got[20])
	}
}
