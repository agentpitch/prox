package app

import (
	"context"
	"runtime"
	"time"

	"github.com/agentpitch/prox/internal/util"
)

type memoryTrimMonitor interface {
	UIActive() bool
}

const (
	idleMemoryTrimInterval   = 5 * time.Minute
	idleHeapReleaseThreshold = 4 << 20
)

func startIdleMemoryTrimmer(ctx context.Context, monitor memoryTrimMonitor) {
	if monitor == nil {
		return
	}
	ticker := time.NewTicker(idleMemoryTrimInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !monitor.UIActive() && idleMemoryReleaseWorthwhile() {
				util.ReleaseIdleMemory()
			}
		}
	}
}

func idleMemoryReleaseWorthwhile() bool {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return idleMemoryStatsWorthReleasing(stats)
}

func idleMemoryStatsWorthReleasing(stats runtime.MemStats) bool {
	unreleasedIdle := uint64(0)
	if stats.HeapIdle > stats.HeapReleased {
		unreleasedIdle = stats.HeapIdle - stats.HeapReleased
	}
	// A large live heap (for example, active relay buffers) is not reclaimable.
	// Using HeapAlloc as a trigger forces a full GC and working-set trim every
	// interval even when nothing can be released, causing avoidable page faults.
	return unreleasedIdle >= idleHeapReleaseThreshold
}
