//go:build windows

package util

import "golang.org/x/sys/windows"

var procEmptyWorkingSet = windows.NewLazySystemDLL("psapi.dll").NewProc("EmptyWorkingSet")

func trimWorkingSet() {
	if procEmptyWorkingSet.Find() != nil {
		return
	}
	procEmptyWorkingSet.Call(uintptr(windows.CurrentProcess()))
	// EmptyWorkingSet is a best-effort trim; failure is non-fatal and only means
	// Windows kept the current working set.
}
