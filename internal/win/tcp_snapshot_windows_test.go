//go:build windows

package win

import (
	"testing"
	"time"
)

func TestTCPSnapshotterClearReleasesProcessCache(t *testing.T) {
	snapshotter := NewTCPSnapshotter()
	snapshotter.exeByPID[42] = exeCacheEntry{
		Path:    `C:\stale.exe`,
		Expires: time.Now().Add(time.Hour),
	}

	snapshotter.Clear()

	if snapshotter.exeByPID != nil {
		t.Fatalf("process cache retained %d entries after Clear", len(snapshotter.exeByPID))
	}
	// Clear is deliberately idempotent so shutdown and a dormant transition
	// can race in either order without retaining metadata or panicking.
	snapshotter.Clear()
}
