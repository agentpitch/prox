//go:build windows

package app

import (
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type resourceOSStats struct {
	PrivateBytes        uint64            `json:"private_bytes"`
	WorkingSetBytes     uint64            `json:"working_set_bytes"`
	PeakWorkingSetBytes uint64            `json:"peak_working_set_bytes"`
	PagefileBytes       uint64            `json:"pagefile_bytes"`
	PeakPagefileBytes   uint64            `json:"peak_pagefile_bytes"`
	PageFaultCount      uint32            `json:"page_fault_count"`
	HandleCount         uint32            `json:"handle_count"`
	GDIHandleCount      uint32            `json:"gdi_handle_count"`
	UserHandleCount     uint32            `json:"user_handle_count"`
	UserTimeMs          uint64            `json:"user_time_ms"`
	KernelTimeMs        uint64            `json:"kernel_time_ms"`
	ReadOperationCount  uint64            `json:"read_operation_count"`
	WriteOperationCount uint64            `json:"write_operation_count"`
	OtherOperationCount uint64            `json:"other_operation_count"`
	ReadTransferBytes   uint64            `json:"read_transfer_bytes"`
	WriteTransferBytes  uint64            `json:"write_transfer_bytes"`
	OtherTransferBytes  uint64            `json:"other_transfer_bytes"`
	HandleTypes         map[string]uint32 `json:"handle_types,omitempty"`
}

type processMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

type processIOCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type systemHandleTableEntryInfoEx struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

type objectTypeInformation struct {
	TypeName windows.NTUnicodeString
}

const (
	systemExtendedHandleInformation = 64
	objectTypeInformationClass      = 2
	statusInfoLengthMismatch        = 0xC0000004
	statusBufferOverflow            = 0x80000005
	statusBufferTooSmall            = 0xC0000023
)

var (
	resourceKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	resourceNtdll             = windows.NewLazySystemDLL("ntdll.dll")
	resourcePsapi             = windows.NewLazySystemDLL("psapi.dll")
	resourceUser32            = windows.NewLazySystemDLL("user32.dll")
	procNtQuerySystemInfo     = resourceNtdll.NewProc("NtQuerySystemInformation")
	procNtQueryObject         = resourceNtdll.NewProc("NtQueryObject")
	procGetProcessMemoryInfo  = resourcePsapi.NewProc("GetProcessMemoryInfo")
	procGetProcessHandleCount = resourceKernel32.NewProc("GetProcessHandleCount")
	procGetProcessTimes       = resourceKernel32.NewProc("GetProcessTimes")
	procGetProcessIoCounters  = resourceKernel32.NewProc("GetProcessIoCounters")
	procGetGuiResources       = resourceUser32.NewProc("GetGuiResources")

	resourceHandleTypeMu    sync.Mutex
	resourceHandleTypeCache = map[uint16]string{}
)

func readResourceOSStats(includeHandleTypes bool) (resourceOSStats, error) {
	var out resourceOSStats
	var errs []error
	h := windows.CurrentProcess()

	mem := processMemoryCountersEx{CB: uint32(unsafe.Sizeof(processMemoryCountersEx{}))}
	if r1, _, err := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mem)), uintptr(mem.CB)); r1 == 0 {
		errs = append(errs, fmt.Errorf("GetProcessMemoryInfo: %w", err))
	} else {
		out.PrivateBytes = uint64(mem.PrivateUsage)
		out.WorkingSetBytes = uint64(mem.WorkingSetSize)
		out.PeakWorkingSetBytes = uint64(mem.PeakWorkingSetSize)
		out.PagefileBytes = uint64(mem.PagefileUsage)
		out.PeakPagefileBytes = uint64(mem.PeakPagefileUsage)
		out.PageFaultCount = mem.PageFaultCount
	}

	var handles uint32
	if r1, _, err := procGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&handles))); r1 == 0 {
		errs = append(errs, fmt.Errorf("GetProcessHandleCount: %w", err))
	} else {
		out.HandleCount = handles
	}

	if r1, _, _ := procGetGuiResources.Call(uintptr(h), 0); r1 != 0 {
		out.GDIHandleCount = uint32(r1)
	}
	if r1, _, _ := procGetGuiResources.Call(uintptr(h), 1); r1 != 0 {
		out.UserHandleCount = uint32(r1)
	}

	var creation, exit, kernel, user windows.Filetime
	if r1, _, err := procGetProcessTimes.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	); r1 == 0 {
		errs = append(errs, fmt.Errorf("GetProcessTimes: %w", err))
	} else {
		out.KernelTimeMs = filetimeDurationMs(kernel)
		out.UserTimeMs = filetimeDurationMs(user)
	}

	var io processIOCounters
	if r1, _, err := procGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&io))); r1 == 0 {
		errs = append(errs, fmt.Errorf("GetProcessIoCounters: %w", err))
	} else {
		out.ReadOperationCount = io.ReadOperationCount
		out.WriteOperationCount = io.WriteOperationCount
		out.OtherOperationCount = io.OtherOperationCount
		out.ReadTransferBytes = io.ReadTransferCount
		out.WriteTransferBytes = io.WriteTransferCount
		out.OtherTransferBytes = io.OtherTransferCount
	}

	if includeHandleTypes {
		types, err := readResourceHandleTypeCounts()
		if err != nil {
			errs = append(errs, fmt.Errorf("handle types: %w", err))
		} else {
			out.HandleTypes = types
		}
	}

	if len(errs) > 0 {
		return out, errorsJoin(errs)
	}
	return out, nil
}

func filetimeDurationMs(ft windows.Filetime) uint64 {
	raw := (uint64(ft.HighDateTime) << 32) | uint64(ft.LowDateTime)
	return raw / 10_000
}

func readResourceHandleTypeCounts() (map[string]uint32, error) {
	handles, err := resourceSystemHandles()
	if err != nil {
		return nil, err
	}
	pid := uintptr(os.Getpid())
	out := map[string]uint32{}
	for _, h := range handles {
		if h.UniqueProcessID != pid {
			continue
		}
		name := cachedResourceHandleTypeName(h.ObjectTypeIndex, windows.Handle(h.HandleValue))
		out[name]++
	}
	return out, nil
}

func cachedResourceHandleTypeName(index uint16, h windows.Handle) string {
	resourceHandleTypeMu.Lock()
	name := resourceHandleTypeCache[index]
	resourceHandleTypeMu.Unlock()
	if name != "" {
		return name
	}
	resolved, err := resourceHandleTypeName(h)
	if err != nil || resolved == "" {
		resolved = "unknown"
	}
	resourceHandleTypeMu.Lock()
	if existing := resourceHandleTypeCache[index]; existing != "" {
		resolved = existing
	} else {
		resourceHandleTypeCache[index] = resolved
	}
	resourceHandleTypeMu.Unlock()
	return resolved
}

func resourceSystemHandles() ([]systemHandleTableEntryInfoEx, error) {
	size := 1 << 20
	for attempt := 0; attempt < 8; attempt++ {
		buf := make([]byte, size)
		var needed uint32
		status, _, _ := procNtQuerySystemInfo.Call(
			uintptr(systemExtendedHandleInformation),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&needed)),
		)
		if ntStatusOK(status) {
			count := *(*uintptr)(unsafe.Pointer(&buf[0]))
			base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uintptr(0))*2
			raw := unsafe.Slice((*systemHandleTableEntryInfoEx)(unsafe.Pointer(base)), int(count))
			out := make([]systemHandleTableEntryInfoEx, 0, 128)
			pid := uintptr(os.Getpid())
			for _, h := range raw {
				if h.UniqueProcessID == pid {
					out = append(out, h)
				}
			}
			return out, nil
		}
		if status != statusInfoLengthMismatch && status != statusBufferOverflow && status != statusBufferTooSmall {
			return nil, windows.NTStatus(uint32(status))
		}
		if needed > uint32(size) {
			size = int(needed) + 64*1024
		} else {
			size *= 2
		}
	}
	return nil, fmt.Errorf("NtQuerySystemInformation: handle table is too large")
}

func resourceHandleTypeName(h windows.Handle) (string, error) {
	size := 4096
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		var needed uint32
		status, _, _ := procNtQueryObject.Call(
			uintptr(h),
			uintptr(objectTypeInformationClass),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&needed)),
		)
		if ntStatusOK(status) {
			info := (*objectTypeInformation)(unsafe.Pointer(&buf[0]))
			return info.TypeName.String(), nil
		}
		if status != statusInfoLengthMismatch && status != statusBufferOverflow && status != statusBufferTooSmall {
			return "", windows.NTStatus(uint32(status))
		}
		if needed > uint32(size) {
			size = int(needed)
		} else {
			size *= 2
		}
	}
	return "", fmt.Errorf("NtQueryObject: type buffer is too small")
}

func ntStatusOK(status uintptr) bool {
	return int32(uint32(status)) >= 0
}

func errorsJoin(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msg := errs[0].Error()
	for _, err := range errs[1:] {
		msg += "; " + err.Error()
	}
	return fmt.Errorf("%s", msg)
}
