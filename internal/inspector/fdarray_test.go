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
