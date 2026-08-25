package inspector

import (
	"testing"

	"github.com/cilium/ebpf"
)

// TestUndumpableReason pins which map types report as undumpable, and that
// every one of them explains itself. ListMaps derives Dumpable from this same
// string being empty, so a type that returns a reason can never also be
// advertised as dumpable.
func TestUndumpableReason(t *testing.T) {
	undumpable := []ebpf.MapType{ebpf.RingBuf, ebpf.PerfEventArray, ebpf.Queue, ebpf.Stack}
	for _, mt := range undumpable {
		if got := undumpableReason(mt); got == "" {
			t.Errorf("undumpableReason(%v) = \"\", want a reason", mt)
		}
	}

	dumpable := []ebpf.MapType{ebpf.Hash, ebpf.Array, ebpf.LRUHash, ebpf.PerCPUArray, ebpf.LPMTrie}
	for _, mt := range dumpable {
		if got := undumpableReason(mt); got != "" {
			t.Errorf("undumpableReason(%v) = %q, want \"\"", mt, got)
		}
	}
}
