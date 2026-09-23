// Package platformcrypto provides the cryptographic operations used by updates.
// Windows uses the operating system's CNG implementation so a dormant proxy does
// not retain Go's TLS/FIPS runtime and its large static entropy buffer.
package platformcrypto

// SHA256 hashes data with the platform implementation.
func SHA256(data []byte) ([32]byte, error) {
	h, err := NewSHA256()
	if err != nil {
		return [32]byte{}, err
	}
	defer h.Close()
	if _, err := h.Write(data); err != nil {
		return [32]byte{}, err
	}
	return h.Sum()
}
