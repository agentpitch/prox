//go:build !windows

package win

import (
	"net/netip"
	"time"
)

type TCPConnection struct {
	PID        uint32
	ExePath    string
	LocalIP    netip.Addr
	LocalPort  uint16
	RemoteIP   netip.Addr
	RemotePort uint16
	State      uint32
	IPv6       bool
	SeenAt     time.Time
}

func ListTCPConnections() ([]TCPConnection, error) { return nil, nil }
