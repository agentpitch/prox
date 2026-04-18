//go:build !windows

package util

import "fmt"

func IsElevated() bool { return true }

func RequireElevation(command string) error { return nil }

func RelaunchSelfElevated(args []string) error {
	_ = args
	return fmt.Errorf("elevation relaunch is only supported on Windows")
}
