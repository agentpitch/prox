package app

import (
	"context"
	"runtime/debug"
	"time"
)

type memoryTrimMonitor interface {
	UIActive() bool
}

const idleMemoryTrimInterval = 2 * time.Minute

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
			if !monitor.UIActive() {
				debug.FreeOSMemory()
			}
		}
	}
}
