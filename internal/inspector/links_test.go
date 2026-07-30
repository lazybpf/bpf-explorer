package inspector

import (
	"testing"

	"github.com/cilium/ebpf/link"
)

// TestLinkTypeName checks the hand-maintained link-type numbering against a few
// well-known values and the fallback for an unknown type.
func TestLinkTypeName(t *testing.T) {
	cases := map[link.Type]string{
		6:                 "xdp",
		linkTypePerfEvent: "perf_event",
		8:                 "kprobe_multi",
		99:                "type(99)",
	}
	for typ, want := range cases {
		if got := linkTypeName(typ); got != want {
			t.Errorf("linkTypeName(%d) = %q, want %q", typ, got, want)
		}
	}
}

// TestPerfEventSubNames pins the perf_event sub-type numbering (uapi
// bpf_perf_event_type), the values perfEventAttach formats.
func TestPerfEventSubNames(t *testing.T) {
	want := map[uint32]string{
		1: "uprobe", 2: "uretprobe", 3: "kprobe",
		4: "kretprobe", 5: "tracepoint", 6: "event",
	}
	for v, name := range want {
		if got := perfEventSubNames[v]; got != name {
			t.Errorf("perfEventSubNames[%d] = %q, want %q", v, got, name)
		}
	}
}
