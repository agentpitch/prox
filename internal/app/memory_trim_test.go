package app

import (
	"runtime"
	"testing"
)

func TestIdleMemoryReleaseRequiresReclaimablePages(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stats runtime.MemStats
		want  bool
	}{
		{"large live heap", runtime.MemStats{HeapAlloc: 128 << 20}, false},
		{"already released", runtime.MemStats{HeapIdle: 32 << 20, HeapReleased: 32 << 20}, false},
		{"small idle remainder", runtime.MemStats{HeapIdle: 32 << 20, HeapReleased: 31 << 20}, false},
		{"reclaimable pages", runtime.MemStats{HeapIdle: 32 << 20, HeapReleased: 24 << 20}, true},
		{"released exceeds idle", runtime.MemStats{HeapIdle: 8 << 20, HeapReleased: 16 << 20}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := idleMemoryStatsWorthReleasing(tc.stats); got != tc.want {
				t.Fatalf("worth releasing = %v, want %v", got, tc.want)
			}
		})
	}
}
