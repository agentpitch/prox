package util

import (
	"runtime/debug"
	"sync/atomic"
	"time"
)

const idleMemoryReleaseMinInterval = time.Second

var (
	lastIdleMemoryReleaseUnixNano atomic.Int64
	idleMemoryReleaseScheduled    atomic.Bool
)

func ReleaseIdleMemory() {
	now := time.Now().UnixNano()
	for {
		last := lastIdleMemoryReleaseUnixNano.Load()
		if last != 0 && time.Duration(now-last) < idleMemoryReleaseMinInterval {
			scheduleIdleMemoryRelease(idleMemoryReleaseMinInterval - time.Duration(now-last))
			return
		}
		if lastIdleMemoryReleaseUnixNano.CompareAndSwap(last, now) {
			break
		}
	}
	debug.FreeOSMemory()
	trimWorkingSet()
}

func scheduleIdleMemoryRelease(delay time.Duration) {
	if delay < 10*time.Millisecond {
		delay = 10 * time.Millisecond
	}
	if !idleMemoryReleaseScheduled.CompareAndSwap(false, true) {
		return
	}
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		<-timer.C
		idleMemoryReleaseScheduled.Store(false)
		ReleaseIdleMemory()
	}()
}
