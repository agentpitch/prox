//go:build windows

package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procIsUserAnAdmin      = windows.NewLazySystemDLL("shell32.dll").NewProc("IsUserAnAdmin")
	procShellExecuteRunasW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteW")
)

func IsElevated() bool {
	r1, _, _ := procIsUserAnAdmin.Call()
	return r1 != 0
}

func RequireElevation(command string) error {
	if IsElevated() {
		return nil
	}
	return fmt.Errorf("%s requires an elevated shell. Re-run PowerShell or Terminal as Administrator", command)
}

func RelaunchSelfElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := windows.UTF16PtrFromString(buildWindowsArgs(args))
	if err != nil {
		return err
	}
	workdir, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return err
	}
	r1, _, callErr := procShellExecuteRunasW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(target)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(workdir)),
		1,
	)
	if r1 <= 32 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return fmt.Errorf("ShellExecuteW(runas): %w", callErr)
		}
		return fmt.Errorf("ShellExecuteW(runas) failed with code %d", r1)
	}
	return nil
}

func buildWindowsArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		parts = append(parts, quoteWindowsArg(arg))
	}
	return strings.Join(parts, " ")
}


func quoteWindowsArg(arg string) string {
	return syscall.EscapeArg(arg)
}
