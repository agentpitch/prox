//go:build windows

package win

import "testing"

func TestDecodeTCPTablesValidateBeforeReadingRows(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"empty table", []byte{0, 0, 0, 0}, false},
		{"missing header", nil, true},
		{"short header", []byte{0, 0, 0}, true},
		{"missing row", []byte{1, 0, 0, 0}, true},
		{"oversized count", []byte{255, 255, 255, 255}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows4, err4 := decodeTCP4Table(tc.data)
			rows6, err6 := decodeTCP6Table(tc.data)
			if (err4 != nil) != tc.wantErr || (err6 != nil) != tc.wantErr {
				t.Fatalf("IPv4 error=%v IPv6 error=%v wantErr=%v", err4, err6, tc.wantErr)
			}
			if len(rows4) != 0 || len(rows6) != 0 {
				t.Fatal("invalid table produced rows")
			}
		})
	}
}
