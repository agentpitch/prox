package platformcrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSHA256KnownVectorsAndStreaming(t *testing.T) {
	for _, test := range []struct{ input, digest string }{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
	} {
		got, err := SHA256([]byte(test.input))
		if err != nil || hex.EncodeToString(got[:]) != test.digest {
			t.Fatalf("SHA256(%q) = %x, %v", test.input, got, err)
		}
	}
	data := bytes.Repeat([]byte("bounded streaming release verification\n"), 100000)
	h, err := NewSHA256()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for pos := 0; pos < len(data); {
		end := min(pos+317, len(data))
		n, err := h.Write(data[pos:end])
		if err != nil || n != end-pos {
			t.Fatalf("Write: %d, %v", n, err)
		}
		pos = end
	}
	got, err := h.Sum()
	if err != nil || got != sha256.Sum256(data) {
		t.Fatalf("stream digest: %x, %v", got, err)
	}
	again, err := h.Sum()
	if err != nil || again != got {
		t.Fatalf("repeated Sum: %x, %v", again, err)
	}
	if _, err := h.Write([]byte("late")); err == nil {
		t.Fatal("write after finish accepted")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHashClosedBeforeFinishFails(t *testing.T) {
	h, err := NewSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Sum(); err == nil {
		t.Fatal("closed hash returned a digest")
	}
	if _, err := h.Write(nil); err == nil {
		t.Fatal("closed hash accepted write")
	}
}

func TestRandomFillsDestinationAndSupportsEmpty(t *testing.T) {
	if err := Random(nil); err != nil {
		t.Fatal(err)
	}
	var first, second [32]byte
	if err := Random(first[:]); err != nil {
		t.Fatal(err)
	}
	if err := Random(second[:]); err != nil {
		t.Fatal(err)
	}
	if first == [32]byte{} || second == [32]byte{} || first == second {
		t.Fatal("RNG produced unchanged or repeated buffer")
	}
}
