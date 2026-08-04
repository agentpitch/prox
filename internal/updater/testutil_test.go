package updater

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

const updaterTestCleanupTimeout = 2 * time.Second

func updaterTestTempDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	directory, err := os.MkdirTemp("", "pitchprox-updater-test-*")
	if err != nil {
		t.Fatalf("create updater test directory: %v", err)
	}
	t.Cleanup(func() {
		if err := removeUpdaterTestDirectory(directory, updaterTestCleanupTimeout); err != nil {
			t.Errorf("remove updater test directory: %v", err)
		}
	})
	return directory
}

func removeUpdaterTestDirectory(directory string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	delay := time.Millisecond
	for {
		err := os.RemoveAll(directory)
		if err == nil || !isRetryableWindowsTestCleanup(err) || time.Now().Add(delay).After(deadline) {
			return err
		}
		time.Sleep(delay)
		if delay < 50*time.Millisecond {
			delay *= 2
		}
	}
}

func isRetryableWindowsTestCleanup(err error) bool {
	// Go's testing.TempDir retries ERROR_ACCESS_DENIED on Windows, but not the
	// equally transient ERROR_DIR_NOT_EMPTY produced while closed NTFS entries
	// are still delete-pending after atomic replace tests.
	return runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(5)) || errors.Is(err, syscall.Errno(145)))
}
