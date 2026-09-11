package inspector

import (
	"encoding/binary"
	"testing"
)

// TestInnerMapID pins how a map-of-maps slot's value is read: the kernel writes
// the inner map's id there as a host-order u32. Both the listing and the dump
// decode slots through this, so they cannot disagree about which map a slot
// holds.
func TestInnerMapID(t *testing.T) {
	value := make([]byte, 4)
	binary.NativeEndian.PutUint32(value, 18798)
	if got := innerMapID(value); got != 18798 {
		t.Errorf("innerMapID = %d, want 18798", got)
	}

	// An empty slot reads back as 0, which is not a valid map id - the callers
	// use that to mean "nothing here" rather than "map 0".
	if got := innerMapID([]byte{0, 0, 0, 0}); got != 0 {
		t.Errorf("innerMapID(empty slot) = %d, want 0", got)
	}

	// Short or missing values are a read that did not happen, not an id.
	for _, short := range [][]byte{nil, {}, {1}, {1, 0, 0}} {
		if got := innerMapID(short); got != 0 {
			t.Errorf("innerMapID(%v) = %d, want 0", short, got)
		}
	}
}
