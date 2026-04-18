//go:build windows

package windivert

import (
	"fmt"
	"syscall"
	"unsafe"
)

const LayerNetwork = 0

type Handle uintptr

type Address struct{ Raw [128]byte }

var (
	modWinDivert      = syscall.NewLazyDLL("WinDivert.dll")
	procOpen          = modWinDivert.NewProc("WinDivertOpen")
	procRecv          = modWinDivert.NewProc("WinDivertRecv")
	procSend          = modWinDivert.NewProc("WinDivertSend")
	procClose         = modWinDivert.NewProc("WinDivertClose")
	procCalcChecksums = modWinDivert.NewProc("WinDivertHelperCalcChecksums")
)

func Open(filter string, layer uint32, priority int16, flags uint64) (Handle, error) {
	cstr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	h, _, callErr := procOpen.Call(uintptr(unsafe.Pointer(cstr)), uintptr(layer), uintptr(uint16(priority)), uintptr(flags))
	if h == 0 || h == ^uintptr(0) {
		if callErr != syscall.Errno(0) {
			return 0, fmt.Errorf("WinDivertOpen: %w", callErr)
		}
		return 0, fmt.Errorf("WinDivertOpen failed")
	}
	return Handle(h), nil
}

func (h Handle) Close() error {
	r1, _, err := procClose.Call(uintptr(h))
	if r1 == 0 {
		if err != syscall.Errno(0) {
			return fmt.Errorf("WinDivertClose: %w", err)
		}
		return fmt.Errorf("WinDivertClose failed")
	}
	return nil
}

func (h Handle) Recv(packet []byte, addr *Address) (int, error) {
	var recvLen uint32
	r1, _, err := procRecv.Call(uintptr(h), uintptr(unsafe.Pointer(&packet[0])), uintptr(uint32(len(packet))), uintptr(unsafe.Pointer(&recvLen)), uintptr(unsafe.Pointer(addr)))
	if r1 == 0 {
		if err != syscall.Errno(0) {
			return 0, fmt.Errorf("WinDivertRecv: %w", err)
		}
		return 0, fmt.Errorf("WinDivertRecv failed")
	}
	return int(recvLen), nil
}

func (h Handle) Send(packet []byte, addr *Address) (int, error) {
	var sendLen uint32
	r1, _, err := procSend.Call(uintptr(h), uintptr(unsafe.Pointer(&packet[0])), uintptr(uint32(len(packet))), uintptr(unsafe.Pointer(&sendLen)), uintptr(unsafe.Pointer(addr)))
	if r1 == 0 {
		if err != syscall.Errno(0) {
			return 0, fmt.Errorf("WinDivertSend: %w", err)
		}
		return 0, fmt.Errorf("WinDivertSend failed")
	}
	return int(sendLen), nil
}

func CalcChecksums(packet []byte, addr *Address) error {
	if len(packet) == 0 {
		return nil
	}
	r1, _, err := procCalcChecksums.Call(uintptr(unsafe.Pointer(&packet[0])), uintptr(uint32(len(packet))), uintptr(unsafe.Pointer(addr)), 0)
	if r1 == 0 {
		if err != syscall.Errno(0) {
			return fmt.Errorf("WinDivertHelperCalcChecksums: %w", err)
		}
		return fmt.Errorf("WinDivertHelperCalcChecksums failed")
	}
	return nil
}
