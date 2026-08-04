//go:build !windows

package updater

import (
	"fmt"
	"os"
	"path/filepath"
)

type stubUpdateLock struct{ path string }

func (l *stubUpdateLock) Close() error { return os.Remove(l.path) }

func (l *stubUpdateLock) ReleaseForHandoff() (bool, error) {
	err := l.Close()
	return err == nil, err
}

func acquireUpdateLock(target string) (platformUpdateLock, error) {
	path := filepath.Join(filepath.Dir(target), lockFileName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("another update transaction is active: %w", err)
	}
	_ = file.Close()
	return &stubUpdateLock{path: path}, nil
}

func launchHandoff(HandoffPlan, func() (bool, error)) error {
	return fmt.Errorf("automatic update is supported only on Windows")
}

func RunHelper(string) error { return fmt.Errorf("automatic update is supported only on Windows") }

func currentProcessStartID() (uint64, error) { return 0, nil }

func replacePath(source, destination string) error { return os.Rename(source, destination) }

func syncUpdateTarget(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
