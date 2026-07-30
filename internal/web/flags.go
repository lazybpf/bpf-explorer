package web

import (
	"fmt"
	"strings"
)

// mapFlagBits maps the kernel BPF_F_* map-creation flags (uapi/linux/bpf.h) to
// short names. Kept as presentation-only decoding of MapInfo.Flags; the wire
// format stays the raw uint32.
var mapFlagBits = []struct {
	bit  uint32
	name string
}{
	{1 << 0, "NO_PREALLOC"},
	{1 << 1, "NO_COMMON_LRU"},
	{1 << 2, "NUMA_NODE"},
	{1 << 3, "RDONLY"},
	{1 << 4, "WRONLY"},
	{1 << 5, "STACK_BUILD_ID"},
	{1 << 6, "ZERO_SEED"},
	{1 << 7, "RDONLY_PROG"},
	{1 << 8, "WRONLY_PROG"},
	{1 << 9, "CLONE"},
	{1 << 10, "MMAPABLE"},
	{1 << 11, "PRESERVE_ELEMS"},
	{1 << 12, "INNER_MAP"},
	{1 << 13, "LINK"},
	{1 << 14, "PATH_FD"},
}

// mapFlags renders a map's flag bitmask as "NAME | NAME" names. Unknown bits are
// appended as hex so nothing is silently dropped; zero renders as "-".
func mapFlags(flags uint32) string {
	if flags == 0 {
		return "-"
	}
	remaining := flags
	var parts []string
	for _, f := range mapFlagBits {
		if flags&f.bit != 0 {
			parts = append(parts, f.name)
			remaining &^= f.bit
		}
	}
	if remaining != 0 {
		parts = append(parts, fmt.Sprintf("0x%x", remaining))
	}
	return strings.Join(parts, " | ")
}
