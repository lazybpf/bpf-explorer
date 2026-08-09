package web

import (
	"encoding/hex"
	"strings"
)

// hexASCII renders a hex-encoded byte string as text, à la the right-hand column
// of `hexdump -C`: printable ASCII as itself, every other byte as ".". It is a
// decoding hint for raw key/value bytes, shown as a tooltip on the hex cells of a
// map dump.
//
// Returns "" - no tooltip - when the input isn't decodable hex or holds no
// printable byte at all, so a purely numeric key or counter doesn't get a
// tooltip of nothing but dots.
func hexASCII(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(b))
	printable := false
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			printable = true
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('.')
	}
	if !printable {
		return ""
	}
	return sb.String()
}
