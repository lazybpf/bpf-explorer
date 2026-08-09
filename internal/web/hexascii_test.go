package web

import "testing"

func TestHexASCII(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"comm string padded with NULs", "62617368000000000000000000000000", "bash............"},
		{"printable text", "68656c6c6f", "hello"},
		{"mixed printable and binary", "0068690a", ".hi."},
		{"u32 counter: no printable byte, no tooltip", "01000000", ""},
		{"all zeroes", "0000000000000000", ""},
		{"odd length is not hex", "abc", ""},
		{"non-hex characters", "zz", ""},
		{"empty", "", ""},
		{"uppercase hex decodes", "48490A", "HI."},
		{"space counts as printable", "20", " "},
		{"DEL and high bytes are dots", "7f80ff41", "...A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hexASCII(tt.in); got != tt.want {
				t.Errorf("hexASCII(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
