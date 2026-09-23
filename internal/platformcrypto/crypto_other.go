//go:build !windows

package platformcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
)

type SHA256Hash struct {
	hash     hash.Hash
	digest   [32]byte
	finished bool
	closed   bool
}

func NewSHA256() (*SHA256Hash, error) { return &SHA256Hash{hash: sha256.New()}, nil }

func (h *SHA256Hash) Write(data []byte) (int, error) {
	if h.closed || h.finished {
		return 0, errors.New("SHA256 hash is closed or finalized")
	}
	return h.hash.Write(data)
}

func (h *SHA256Hash) Sum() ([32]byte, error) {
	if h.finished {
		return h.digest, nil
	}
	if h.closed {
		return [32]byte{}, errors.New("SHA256 hash is closed")
	}
	copy(h.digest[:], h.hash.Sum(nil))
	h.finished = true
	return h.digest, nil
}

func (h *SHA256Hash) Close() error {
	if h != nil {
		h.closed = true
		h.hash = nil
	}
	return nil
}

func Random(data []byte) error { _, err := rand.Read(data); return err }
