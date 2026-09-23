//go:build windows

package util

import (
	"os"

	"golang.org/x/sys/windows"
)

var procAttachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

// PrepareCLIConsole enables commands in the GUI-subsystem executable without
// opening a console window. Preserve inherited pipes/files used by agents and
// PowerShell, and attach only missing streams to the parent's existing console.
func PrepareCLIConsole() {
	slots := []struct {
		id   uint32
		file **os.File
		name string
	}{
		{windows.STD_INPUT_HANDLE, &os.Stdin, "/dev/stdin"},
		{windows.STD_OUTPUT_HANDLE, &os.Stdout, "/dev/stdout"},
		{windows.STD_ERROR_HANDLE, &os.Stderr, "/dev/stderr"},
	}
	var preserved [3]windows.Handle
	missing := false
	for i, slot := range slots {
		if *slot.file != nil {
			handle := windows.Handle((*slot.file).Fd())
			if handle != 0 && handle != windows.InvalidHandle {
				if _, err := windows.GetFileType(handle); err == nil {
					preserved[i] = handle
					continue
				}
			}
		}
		missing = true
	}
	if !missing {
		return
	}
	procAttachConsole.Call(uintptr(^uint32(0))) // ATTACH_PARENT_PROCESS
	for i, slot := range slots {
		if preserved[i] != 0 {
			_ = windows.SetStdHandle(slot.id, preserved[i])
			continue
		}
		if handle, err := windows.GetStdHandle(slot.id); err == nil && handle != 0 && handle != windows.InvalidHandle {
			*slot.file = os.NewFile(uintptr(handle), slot.name)
		}
	}
}
