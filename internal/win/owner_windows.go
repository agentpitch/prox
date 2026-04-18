//go:build windows

package win

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIPHLPAPI          = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTable = modIPHLPAPI.NewProc("GetExtendedTcpTable")
)

const (
	afInet                  = 2
	afInet6                 = 23
	tcpTableOwnerPIDConnect = 4
	tcpTableOwnerPIDAll     = 5
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	RemoteAddr   [16]byte
	RemoteScope  uint32
	RemotePort   uint32
	State        uint32
	OwningPID    uint32
}

func FindTCPProcess(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (uint32, error) {
	srcIP = srcIP.Unmap()
	dstIP = dstIP.Unmap()
	if srcIP.Is4() && dstIP.Is4() {
		return findTCP4(srcIP, srcPort, dstIP, dstPort)
	}
	if srcIP.Is6() && dstIP.Is6() {
		return findTCP6(srcIP, srcPort, dstIP, dstPort)
	}
	return 0, fmt.Errorf("address family mismatch")
}

func findTCP4(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (uint32, error) {
	rows, err := loadTCP4Table(tcpTableOwnerPIDConnect)
	if err == nil {
		if pid, ok := matchTCP4Exact(rows, srcIP, srcPort, dstIP, dstPort); ok {
			return pid, nil
		}
	}
	rows, err = loadTCP4Table(tcpTableOwnerPIDAll)
	if err != nil {
		return 0, err
	}
	if pid, ok := matchTCP4Exact(rows, srcIP, srcPort, dstIP, dstPort); ok {
		return pid, nil
	}
	if pid, ok := matchTCP4Local(rows, srcIP, srcPort); ok {
		return pid, nil
	}
	return 0, fmt.Errorf("tcp4 owner not found")
}

func matchTCP4Exact(rows []mibTCPRowOwnerPID, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (uint32, bool) {
	src := srcIP.As4()
	dst := dstIP.As4()
	srcU := binary.LittleEndian.Uint32(src[:])
	dstU := binary.LittleEndian.Uint32(dst[:])
	for _, row := range rows {
		if row.LocalAddr == srcU && row.RemoteAddr == dstU && decodePort(row.LocalPort) == srcPort && decodePort(row.RemotePort) == dstPort {
			return row.OwningPID, true
		}
	}
	return 0, false
}

func matchTCP4Local(rows []mibTCPRowOwnerPID, srcIP netip.Addr, srcPort uint16) (uint32, bool) {
	src := srcIP.As4()
	srcU := binary.LittleEndian.Uint32(src[:])
	for _, row := range rows {
		if row.LocalAddr == srcU && decodePort(row.LocalPort) == srcPort && row.OwningPID != 0 {
			return row.OwningPID, true
		}
	}
	return 0, false
}

func findTCP6(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (uint32, error) {
	rows, err := loadTCP6Table(tcpTableOwnerPIDConnect)
	if err == nil {
		if pid, ok := matchTCP6Exact(rows, srcIP, srcPort, dstIP, dstPort); ok {
			return pid, nil
		}
	}
	rows, err = loadTCP6Table(tcpTableOwnerPIDAll)
	if err != nil {
		return 0, err
	}
	if pid, ok := matchTCP6Exact(rows, srcIP, srcPort, dstIP, dstPort); ok {
		return pid, nil
	}
	if pid, ok := matchTCP6Local(rows, srcIP, srcPort); ok {
		return pid, nil
	}
	return 0, fmt.Errorf("tcp6 owner not found")
}

func matchTCP6Exact(rows []mibTCP6RowOwnerPID, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (uint32, bool) {
	src := srcIP.As16()
	dst := dstIP.As16()
	for _, row := range rows {
		if row.LocalAddr == src && row.RemoteAddr == dst && decodePort(row.LocalPort) == srcPort && decodePort(row.RemotePort) == dstPort {
			return row.OwningPID, true
		}
	}
	return 0, false
}

func matchTCP6Local(rows []mibTCP6RowOwnerPID, srcIP netip.Addr, srcPort uint16) (uint32, bool) {
	src := srcIP.As16()
	for _, row := range rows {
		if row.LocalAddr == src && decodePort(row.LocalPort) == srcPort && row.OwningPID != 0 {
			return row.OwningPID, true
		}
	}
	return 0, false
}

func loadTCP4Table(tableClass uint32) ([]mibTCPRowOwnerPID, error) {
	buf, err := loadTable(afInet, tableClass)
	if err != nil {
		return nil, err
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	rows := make([]mibTCPRowOwnerPID, 0, n)
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	base := uintptr(unsafe.Pointer(&buf[4]))
	for i := uint32(0); i < n; i++ {
		row := *(*mibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))
		rows = append(rows, row)
	}
	return rows, nil
}

func loadTCP6Table(tableClass uint32) ([]mibTCP6RowOwnerPID, error) {
	buf, err := loadTable(afInet6, tableClass)
	if err != nil {
		return nil, err
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	rows := make([]mibTCP6RowOwnerPID, 0, n)
	rowSize := unsafe.Sizeof(mibTCP6RowOwnerPID{})
	base := uintptr(unsafe.Pointer(&buf[4]))
	for i := uint32(0); i < n; i++ {
		row := *(*mibTCP6RowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))
		rows = append(rows, row)
	}
	return rows, nil
}

func loadTable(af uint32, tableClass uint32) ([]byte, error) {
	var size uint32
	r1, _, _ := procGetExtendedTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(tableClass), 0)
	if r1 != 0 && windows.Errno(r1) != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, syscallErr("GetExtendedTcpTable", r1)
	}
	if size < 4 {
		size = 4
	}
	buf := make([]byte, size)
	r1, _, _ = procGetExtendedTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(tableClass), 0)
	if r1 != 0 {
		return nil, syscallErr("GetExtendedTcpTable", r1)
	}
	return buf[:size], nil
}

func decodePort(v uint32) uint16 {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return binary.BigEndian.Uint16(b[:2])
}

func ExePath(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func syscallErr(name string, code uintptr) error {
	return fmt.Errorf("%s: %w", name, windows.Errno(code))
}
