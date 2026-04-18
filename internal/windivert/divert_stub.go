//go:build !windows

package windivert

import "fmt"

const LayerNetwork = 0

type Handle uintptr

type Address struct{ Raw [128]byte }

func Open(filter string, layer uint32, priority int16, flags uint64) (Handle, error) {
	return 0, fmt.Errorf("windows only")
}
func (h Handle) Close() error                                   { return nil }
func (h Handle) Recv(packet []byte, addr *Address) (int, error) { return 0, fmt.Errorf("windows only") }
func (h Handle) Send(packet []byte, addr *Address) (int, error) { return 0, fmt.Errorf("windows only") }
func CalcChecksums(packet []byte, addr *Address) error          { return nil }
