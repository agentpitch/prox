//go:build windows

package util

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	swHide = 0
)

var (
	procGetConsoleWindow      = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow")
	procGetConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	procShowWindow            = windows.NewLazySystemDLL("user32.dll").NewProc("ShowWindow")
)

// HideConsoleIfOwn hides the console window only when the current process owns
// a private console created just for it (for example when launched by double click
// from Explorer). It avoids hiding an existing PowerShell/Terminal window.
func HideConsoleIfOwn() bool {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return false
	}
	// A private console created for this process usually has exactly one attached
	// process. When launched from an existing shell there are multiple processes
	// attached to the same console, so we do not hide it.
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if n != 1 {
		return false
	}
	procShowWindow.Call(hwnd, swHide)
	return true
}
