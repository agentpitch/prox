package util

import (
	"net"
	"net/netip"
)

func LocalIPs() (map[netip.Addr]struct{}, error) {
	out := map[netip.Addr]struct{}{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if a, ok := netip.AddrFromSlice(ip); ok {
				out[a.Unmap()] = struct{}{}
			}
		}
	}
	out[netip.MustParseAddr("127.0.0.1")] = struct{}{}
	out[netip.MustParseAddr("::1")] = struct{}{}
	return out, nil
}
