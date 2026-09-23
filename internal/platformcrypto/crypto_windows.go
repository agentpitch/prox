//go:build windows

package platformcrypto

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	bcrypt         = windows.NewLazySystemDLL("bcrypt.dll")
	openAlgorithm  = bcrypt.NewProc("BCryptOpenAlgorithmProvider")
	closeAlgorithm = bcrypt.NewProc("BCryptCloseAlgorithmProvider")
	createHash     = bcrypt.NewProc("BCryptCreateHash")
	hashData       = bcrypt.NewProc("BCryptHashData")
	finishHash     = bcrypt.NewProc("BCryptFinishHash")
	destroyHash    = bcrypt.NewProc("BCryptDestroyHash")
	genRandom      = bcrypt.NewProc("BCryptGenRandom")
)

// SHA256Hash owns its native provider and hash object. Call Close even when a
// write fails. Like hash.Hash, a SHA256Hash is not safe for concurrent use.
type SHA256Hash struct {
	provider uintptr
	handle   uintptr
	digest   [32]byte
	err      error
	finished bool
	closed   bool
}

func cngError(operation string, status uintptr) error {
	if int32(status) >= 0 {
		return nil
	}
	return fmt.Errorf("%s: NTSTATUS %#08x", operation, uint32(status))
}

func NewSHA256() (*SHA256Hash, error) {
	h := &SHA256Hash{}
	name := windows.StringToUTF16Ptr("SHA256")
	status, _, _ := openAlgorithm.Call(uintptr(unsafe.Pointer(&h.provider)), uintptr(unsafe.Pointer(name)), 0, 0)
	runtime.KeepAlive(name)
	if err := cngError("BCryptOpenAlgorithmProvider(SHA256)", status); err != nil {
		return nil, err
	}
	// CNG allocates the small hash object when the buffer is nil. DestroyHash
	// releases it; CNG never retains a pointer into the Go heap.
	status, _, _ = createHash.Call(h.provider, uintptr(unsafe.Pointer(&h.handle)), 0, 0, 0, 0, 0)
	if err := cngError("BCryptCreateHash", status); err != nil {
		_ = h.Close()
		return nil, err
	}
	return h, nil
}

func (h *SHA256Hash) Write(data []byte) (int, error) {
	if h.closed || h.finished {
		return 0, errors.New("SHA256 hash is closed or finalized")
	}
	if h.err != nil {
		return 0, h.err
	}
	written := 0
	for len(data) > 0 {
		n := min(len(data), 1<<20)
		status, _, _ := hashData.Call(h.handle, uintptr(unsafe.Pointer(&data[0])), uintptr(n), 0)
		runtime.KeepAlive(data)
		if h.err = cngError("BCryptHashData", status); h.err != nil {
			return written, h.err
		}
		written += n
		data = data[n:]
	}
	return written, nil
}

// Sum finalizes the hash. Further calls return the same digest; writes after
// finalization are rejected. Native errors are returned rather than accepted as
// a digest or converted into a process-wide panic.
func (h *SHA256Hash) Sum() ([32]byte, error) {
	if h.err != nil {
		return [32]byte{}, h.err
	}
	if h.finished {
		return h.digest, nil
	}
	if h.closed {
		return [32]byte{}, errors.New("SHA256 hash is closed")
	}
	status, _, _ := finishHash.Call(h.handle, uintptr(unsafe.Pointer(&h.digest[0])), uintptr(len(h.digest)), 0)
	runtime.KeepAlive(h)
	if h.err = cngError("BCryptFinishHash", status); h.err != nil {
		return [32]byte{}, h.err
	}
	h.finished = true
	return h.digest, nil
}

func (h *SHA256Hash) Close() error {
	if h == nil || h.closed {
		return nil
	}
	h.closed = true
	var hashErr, providerErr error
	if h.handle != 0 {
		status, _, _ := destroyHash.Call(h.handle)
		hashErr = cngError("BCryptDestroyHash", status)
		h.handle = 0
	}
	if h.provider != 0 {
		status, _, _ := closeAlgorithm.Call(h.provider, 0)
		providerErr = cngError("BCryptCloseAlgorithmProvider", status)
		h.provider = 0
	}
	return errors.Join(hashErr, providerErr)
}

// Random uses the OS cryptographically secure generator. It has no fallback to
// a predictable source if Windows reports an error.
func Random(data []byte) error {
	for len(data) > 0 {
		n := min(len(data), 1<<20)
		status, _, _ := genRandom.Call(0, uintptr(unsafe.Pointer(&data[0])), uintptr(n), 2) // BCRYPT_USE_SYSTEM_PREFERRED_RNG
		runtime.KeepAlive(data)
		if err := cngError("BCryptGenRandom", status); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
