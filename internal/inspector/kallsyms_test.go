package inspector

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// A stand-in for /proc/kallsyms: the address column, the symbol type, the name,
// and for module symbols a bracketed module. The addresses put
// bpf_get_current_uid_gid and bpf_get_current_pid_tgid at exactly the offsets
// from __bpf_call_base that a real dump of ig_execve_e carries.
const symtab = `ffffffff81000000 T __bpf_call_base
ffffffff8103b290 T bpf_get_current_pid_tgid
ffffffff8103b470 T bpf_get_current_uid_gid
ffffffff80fffff0 T bpf_below_base
ffffffffc0012340 t some_kfunc	[test_module]
`

const callBase = 0xffffffff81000000

// helperCall builds the call instruction the verifier leaves behind: imm is an
// offset from __bpf_call_base rather than a helper id.
func helperCall(imm int32) asm.Instruction {
	return asm.Instruction{
		OpCode:   asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call),
		Constant: int64(imm),
	}
}

func TestCallNames(t *testing.T) {
	tests := []struct {
		name  string
		insns asm.Instructions
		syms  string
		want  map[int32]string
	}{
		{
			"helper calls resolve to their symbols",
			asm.Instructions{helperCall(242800), asm.Mov.Reg(asm.R9, asm.R0), helperCall(242320)},
			symtab,
			map[int32]string{242800: "bpf_get_current_uid_gid", 242320: "bpf_get_current_pid_tgid"},
		},
		{
			// A helper below __bpf_call_base gives a negative imm, which has to
			// subtract rather than wrap into an address nothing sits at.
			"negative offsets subtract from the base",
			asm.Instructions{helperCall(-16)},
			symtab,
			map[int32]string{-16: "bpf_below_base"},
		},
		{
			// kfuncs are patched the same way helpers are, module ones included.
			"kfunc calls resolve too",
			asm.Instructions{{
				OpCode:   asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call),
				Src:      asm.PseudoKfuncCall,
				Constant: 0x3f012340,
			}},
			symtab,
			map[int32]string{0x3f012340: "some_kfunc"},
		},
		{
			// A call to another BPF function is a pc-relative offset, not an
			// address, so looking it up would name whatever happened to sit there.
			"bpf-to-bpf calls are not looked up",
			asm.Instructions{{
				OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call),
				Src:    asm.PseudoCall,
				Offset: 6,
			}},
			symtab,
			nil,
		},
		{
			"a program that calls nothing needs no symbols",
			asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			symtab,
			nil,
		},
		{
			// What an unprivileged reader sees, or kernel.kptr_restrict: every
			// name present, every address zeroed.
			"hidden addresses name nothing",
			asm.Instructions{helperCall(242800)},
			"0000000000000000 T __bpf_call_base\n0000000000000000 T bpf_get_current_uid_gid\n",
			map[int32]string{},
		},
		{
			"an unknown target stays unnamed",
			asm.Instructions{helperCall(1)},
			symtab,
			map[int32]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := callNames(tt.insns, callBase, strings.NewReader(tt.syms))
			if len(got) != len(tt.want) {
				t.Fatalf("callNames() = %v, want %v", got, tt.want)
			}
			for imm, want := range tt.want {
				if got[imm] != want {
					t.Errorf("callNames()[%d] = %q, want %q", imm, got[imm], want)
				}
			}
		})
	}
}

// The symbol table is walked once per dump and a kernel carries ~200k symbols,
// so the scan has to stop as soon as every call has a name rather than read on.
// The tail here is far larger than any buffer the scanner reads ahead into, so
// an unread remainder means the scan really did stop.
func TestCallNamesStopsWhenDone(t *testing.T) {
	var table strings.Builder
	table.WriteString(symtab)
	for i := 0; i < 4000; i++ {
		table.WriteString("ffffffff82000000 T a_symbol_the_scan_should_never_reach\n")
	}

	r := strings.NewReader(table.String())
	callNames(asm.Instructions{helperCall(242800), helperCall(242320)}, callBase, r)

	if r.Len() == 0 {
		t.Error("callNames() read the whole table after naming every call")
	}
}

func TestScanSymbols(t *testing.T) {
	var got []string
	scanSymbols(strings.NewReader(symtab), func(addr uint64, name string) bool {
		got = append(got, name)
		return true
	})

	want := []string{
		"__bpf_call_base",
		"bpf_get_current_pid_tgid",
		"bpf_get_current_uid_gid",
		"bpf_below_base",
		"some_kfunc",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("scanSymbols() saw %v, want %v", got, want)
	}

	// Returning false ends the scan; this is what lets a dump stop reading
	// once every call it makes has a name.
	var seen int
	scanSymbols(strings.NewReader(symtab), func(addr uint64, name string) bool {
		seen++
		return seen < 2
	})
	if seen != 2 {
		t.Errorf("scanSymbols() yielded %d symbols after fn returned false, want 2", seen)
	}

	// Lines that carry no usable symbol are skipped rather than ending the scan.
	var count int
	scanSymbols(strings.NewReader("\ngarbage\nzzzz T bad_address\n0000000000000000 T hidden\nffffffff81000000 T good\n"),
		func(addr uint64, name string) bool {
			count++
			if name != "good" {
				t.Errorf("scanSymbols() yielded %q, want only \"good\"", name)
			}
			return true
		})
	if count != 1 {
		t.Errorf("scanSymbols() yielded %d symbols, want 1", count)
	}
}

// The want names here are the strings bpftool itself is built with; every one
// of the 211 helpers cilium knows was checked against them, and the awkward
// spellings are the ones worth pinning against a future generator change.
func TestHelperName(t *testing.T) {
	tests := []struct {
		imm  int32
		want string
	}{
		{35, "bpf_get_current_task"},
		{12, "bpf_tail_call"},
		{1, "bpf_map_lookup_elem"},
		{5, "bpf_ktime_get_ns"},
		// One capital per word in the kernel's own name, so a word that runs
		// letters and digits together stays together.
		{8, "bpf_get_smp_processor_id"},
		{10, "bpf_l3_csum_replace"},
		{27, "bpf_get_stackid"},
		{49, "bpf_setsockopt"},
		{136, "bpf_skc_to_tcp6_sock"},
		{147, "bpf_d_path"},
		// Id zero is what the kernel writes over a call it will not show an
		// address for, so it names nothing rather than BPF_FUNC_unspec.
		{0, ""},
		{-16, ""},
		// Beyond the helpers this build of cilium knows.
		{9000, ""},
		// An address offset that found no symbol is not a helper id either,
		// though nothing but its size says so.
		{242800, ""},
	}

	for _, tt := range tests {
		if got := helperName(tt.imm); got != tt.want {
			t.Errorf("helperName(%d) = %q, want %q", tt.imm, got, tt.want)
		}
	}

	// The names come out of cilium's constants, so a change to how it spells
	// them would quietly turn every id-form call back into "unknown". Pin that
	// the table is still being read at all.
	var named int
	for imm := int32(1); imm < 512; imm++ {
		name := helperName(imm)
		if name == "" {
			continue
		}
		named++
		if !strings.HasPrefix(name, "bpf_") || strings.Contains(name, "__") || strings.HasSuffix(name, "_") {
			t.Errorf("helperName(%d) = %q, not a helper name", imm, name)
		}
	}
	if named < 200 {
		t.Errorf("helperName named %d helpers, want the whole table (211 as of cilium v0.22)", named)
	}
}
