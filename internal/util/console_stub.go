//go:build !windows

package util

func HideConsoleIfOwn() bool { return false }
