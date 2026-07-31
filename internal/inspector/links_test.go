package inspector

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// TestLinkTypeName checks the hand-maintained link-type numbering against a few
// well-known values and the fallback for an unknown type.
func TestLinkTypeName(t *testing.T) {
	cases := map[link.Type]string{
		linkTypeRawTracepoint: "raw_tracepoint",
		linkTypeTracing:       "tracing",
		6:                     "xdp",
		linkTypePerfEvent:     "perf_event",
		8:                     "kprobe_multi",
		99:                    "type(99)",
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

// TestTracingAttachTypeName pins the attach-type numbering of the tracing link
// family (uapi bpf_attach_type) - lsm_mac is what an LSM link reports - and the
// fallback for an attach type outside it.
func TestTracingAttachTypeName(t *testing.T) {
	cases := map[uint32]string{
		24: "trace_fentry",
		25: "trace_fexit",
		27: "lsm_mac",
		41: "attach(41)", // perf_event: never on a tracing link
	}
	for typ, want := range cases {
		if got := tracingAttachTypeName(typ); got != want {
			t.Errorf("tracingAttachTypeName(%d) = %q, want %q", typ, got, want)
		}
	}
}

// TestTracingProgTypeName checks the bpftool spelling of the program types that
// can hold a tracing link, and the fallback for one that cannot.
func TestTracingProgTypeName(t *testing.T) {
	cases := map[ebpf.ProgramType]string{
		ebpf.LSM:       "lsm",
		ebpf.Tracing:   "tracing",
		ebpf.Extension: "ext",
		ebpf.XDP:       "prog(6)",
	}
	for typ, want := range cases {
		if got := tracingProgTypeName(typ); got != want {
			t.Errorf("tracingProgTypeName(%d) = %q, want %q", uint32(typ), got, want)
		}
	}
}

// TestTargetTypeName covers the BTF shapes a tracing link's target_btf_id points
// at: a func for LSM/fentry/fexit, and the btf_trace_<name> typedef the kernel
// resolves a tp_btf link to. Anything else is not an attach target.
func TestTargetTypeName(t *testing.T) {
	cases := []struct {
		typ  btf.Type
		want string
	}{
		{&btf.Func{Name: "bpf_lsm_bprm_check_security"}, "bpf_lsm_bprm_check_security"},
		{&btf.Typedef{Name: "btf_trace_sched_switch"}, "sched_switch"},
		{&btf.Typedef{Name: "pid_t"}, ""},
		{&btf.Int{Name: "int"}, ""},
	}
	for _, c := range cases {
		if got := targetTypeName(c.typ); got != c.want {
			t.Errorf("targetTypeName(%s) = %q, want %q", c.typ, got, c.want)
		}
	}
}
