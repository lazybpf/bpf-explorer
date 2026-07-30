package web

import "testing"

func TestMapFlags(t *testing.T) {
	cases := []struct {
		flags uint32
		want  string
	}{
		{0, "-"},
		{1 << 0, "NO_PREALLOC"},
		{1 << 3, "RDONLY"},
		{(1 << 0) | (1 << 3), "NO_PREALLOC | RDONLY"},
		{1 << 10, "MMAPABLE"},
		{1 << 30, "0x40000000"},                       // unknown bit -> hex, not dropped
		{(1 << 3) | (1 << 30), "RDONLY | 0x40000000"}, // known + unknown
	}
	for _, c := range cases {
		if got := mapFlags(c.flags); got != c.want {
			t.Errorf("mapFlags(%#x) = %q, want %q", c.flags, got, c.want)
		}
	}
}
