//go:build !windows

package win

import (
	"fmt"
	"net/netip"
)

func FindTCPProcess(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (uint32, error) {
	return 0, fmt.Errorf("windows only")
}

func ExePath(pid uint32) (string, error) { return "", fmt.Errorf("windows only") }
