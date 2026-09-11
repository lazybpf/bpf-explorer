package inspector

import (
	"encoding/binary"
	"testing"
)

// TestFDArrayID pins how a slot holding a kernel object is read: the kernel
// writes the object's id there as a host-order u32 - an inner map for a
// map-of-maps, a program for a program array. The listing and the dump decode
// slots through this, so they cannot disagree about what a slot holds.
func TestFDArrayID(t *testing.T) {
	value := make([]byte, 4)
	binary.NativeEndian.PutUint32(value, 18798)
	if got := fdArrayID(value); got != 18798 {
		t.Errorf("fdArrayID = %d, want 18798", got)
	}

	// An empty slot reads back as 0, which is not a valid id - the callers use
	// that to mean "nothing here" rather than "map 0" or "program 0".
	if got := fdArrayID([]byte{0, 0, 0, 0}); got != 0 {
		t.Errorf("fdArrayID(empty slot) = %d, want 0", got)
	}

	// Short or missing values are a read that did not happen, not an id.
	for _, short := range [][]byte{nil, {}, {1}, {1, 0, 0}} {
		if got := fdArrayID(short); got != 0 {
			t.Errorf("fdArrayID(%v) = %d, want 0", short, got)
		}
	}
}

// TestFormatIndex pins the key side of the same slot: an array-shaped map is
// addressed by index, and with no BTF to say so the raw key bytes are all the
// dump has. They are a host-order u32, read here the way fdArrayID reads the
// value, so a slot's row says "0" rather than "00 00 00 00".
func TestFormatIndex(t *testing.T) {
	key := make([]byte, 4)
	binary.NativeEndian.PutUint32(key, 7)
	if got := formatIndex(key); got != "7" {
		t.Errorf("formatIndex = %q, want 7", got)
	}

	// Index 0 is a real slot, not an absent one - unlike an id, where 0 means
	// nothing is there.
	if got := formatIndex([]byte{0, 0, 0, 0}); got != "0" {
		t.Errorf("formatIndex(slot 0) = %q, want 0", got)
	}

	// A key that cannot hold an index keeps its bytes rather than inventing one.
	for _, odd := range [][]byte{{1}, {1, 0, 0}, {1, 0, 0, 0, 0}} {
		if got := formatIndex(odd); got != hexBytes(odd) {
			t.Errorf("formatIndex(%v) = %q, want the raw bytes %q", odd, got, hexBytes(odd))
		}
	}
	if got := formatIndex(nil); got != "<empty>" {
		t.Errorf("formatIndex(nil) = %q, want <empty>", got)
	}
}
