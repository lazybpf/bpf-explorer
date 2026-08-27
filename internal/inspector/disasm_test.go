package inspector

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// The want strings are what `bpftool prog dump xlated` prints for the same
// instruction, so a mismatch here is a mismatch with bpftool.
func TestFormatInstruction(t *testing.T) {
	tests := []struct {
		name string
		ins  asm.Instruction
		want string
	}{
		// ALU. The 32-bit class prints w-registers, the 64-bit one r.
		{"mov reg", asm.Mov.Reg(asm.R8, asm.R1), "(bf) r8 = r1"},
		{"add imm, negative", asm.Add.Imm(asm.R2, -4), "(07) r2 += -4"},
		{"add imm, 32 bit", asm.Add.Imm32(asm.R1, 5), "(04) w1 += 5"},
		{"and reg", asm.And.Reg(asm.R1, asm.R2), "(5f) r1 &= r2"},
		{"arithmetic shift", asm.ArSh.Imm(asm.R1, 32), "(c7) r1 s>>= 32"},
		// The signed and sign-extending forms live in the off field on the
		// wire; cilium lifts them into the ALUOp, so they must be read back
		// from there rather than from ins.Offset.
		{"signed divide", asm.SDiv.Reg(asm.R1, asm.R2), "(3f) r1 s/= r2"},
		{"signed modulo", asm.SMod.Reg(asm.R1, asm.R2), "(9f) r1 s%= r2"},
		{"sign-extending mov", asm.MovSX32.Reg(asm.R1, asm.R2), "(bf) r1 = (s32)r2"},
		{"sign-extending mov, 8 bit", asm.MovSX8.Reg(asm.R1, asm.R2), "(bf) r1 = (s8)r2"},
		{"negate", asm.Neg.Imm(asm.R1, 0), "(87) r1 = -r1"},
		{"negate, 32 bit", asm.Neg.Imm32(asm.R1, 0), "(84) w1 = -w1"},
		// Byte swaps take their width from imm, not from the opcode's size
		// bits, and print r-registers even in the 32-bit class.
		{"bswap", asm.BSwap(asm.R1, asm.DWord), "(d7) r1 = bswap64 r1"},
		{"host to big endian", asm.HostTo(asm.BE, asm.R1, asm.Word), "(dc) r1 = be32 r1"},
		{"host to little endian", asm.HostTo(asm.LE, asm.R1, asm.Half), "(d4) r1 = le16 r1"},

		// Loads and stores.
		{"load 64 bit", asm.LoadMem(asm.R1, asm.R8, 24, asm.DWord), "(79) r1 = *(u64 *)(r8 +24)"},
		{"load 8 bit", asm.LoadMem(asm.R3, asm.R1, 0, asm.Byte), "(71) r3 = *(u8 *)(r1 +0)"},
		{"sign-extending load", asm.LoadMemSX(asm.R1, asm.R2, 8, asm.Word), "(81) r1 = *(s32 *)(r2 +8)"},
		{"store reg", asm.StoreMem(asm.R10, -32, asm.R1, asm.DWord), "(7b) *(u64 *)(r10 -32) = r1"},
		{"store reg, 32 bit", asm.StoreMem(asm.R10, -4, asm.R9, asm.Word), "(63) *(u32 *)(r10 -4) = r9"},
		{"store imm", asm.StoreImm(asm.R10, -8, 5, asm.Word), "(62) *(u32 *)(r10 -8) = 5"},

		// Atomics: the plain forms read as compound assignments under a lock,
		// the fetching ones as the kernel's atomic_*() helpers.
		{"atomic add", asm.StoreXAdd(asm.R1, asm.R2, asm.DWord), "(db) lock *(u64 *)(r1 +0) += r2"},
		{"atomic or, 32 bit", asm.OrAtomic.Mem(asm.R1, asm.R2, asm.Word, 4), "(c3) lock *(u32 *)(r1 +4) |= r2"},
		{"atomic fetch add", asm.FetchAdd.Mem(asm.R1, asm.R2, asm.Word, 4), "(c3) r2 = atomic_fetch_add((u32 *)(r1 +4), r2)"},
		{"atomic fetch and, 64 bit", asm.FetchAnd.Mem(asm.R1, asm.R2, asm.DWord, 0), "(db) r2 = atomic64_fetch_and((u64 *)(r1 +0), r2)"},
		{"atomic exchange", asm.Xchg.Mem(asm.R1, asm.R2, asm.DWord, 0), "(db) r2 = atomic64_xchg((u64 *)(r1 +0), r2)"},
		{"atomic compare and exchange", asm.CmpXchg.Mem(asm.R1, asm.R2, asm.DWord, 0), "(db) r0 = atomic64_cmpxchg((u64 *)(r1 +0), r0, r2)"},
		{"nospec barrier", asm.Instruction{OpCode: asm.OpCode(asm.StClass).SetMode(asm.AtomicMode)}, "(c2) nospec"},

		// Double-wide immediate loads. What looks like a file descriptor in the
		// source object is a map id by the time the kernel dumps it back.
		{"map pointer", asm.LoadMapPtr(asm.R1, 422), "(18) r1 = map[id:422]"},
		{"map value", asm.LoadMapValue(asm.R1, 422, 8), "(18) r1 = map[id:422][0]+8"},
		{"plain 64 bit immediate", asm.LoadImm(asm.R1, 0xdeadbeef, asm.DWord), "(18) r1 = 0xdeadbeef"},
		{
			"function pointer",
			asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R1, Src: asm.PseudoFunc, Constant: 4},
			"(18) r1 = subprog[+4]",
		},

		// The legacy packet loads, still emitted for socket filters.
		{"load packet absolute", asm.LoadAbs(12, asm.Half), "(28) r0 = *(u16 *)skb[12]"},
		{"load packet indirect", asm.LoadInd(asm.R0, asm.R3, 4, asm.Word), "(40) r0 = *(u32 *)skb[r3 + 4]"},

		// Jumps. Conditions against an immediate print it as unsigned hex.
		{
			"conditional jump, reg",
			asm.Instruction{OpCode: asm.JGT.Op(asm.RegSource), Dst: asm.R1, Src: asm.R2, Offset: 3},
			"(2d) if r1 > r2 goto pc+3",
		},
		{
			"conditional jump, imm",
			asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R1, Constant: 5, Offset: -2},
			"(15) if r1 == 0x5 goto pc-2",
		},
		{
			"conditional jump, signed",
			asm.Instruction{OpCode: asm.JSLT.Op(asm.ImmSource), Dst: asm.R1, Constant: -1, Offset: 1},
			"(c5) if r1 s< 0xffffffff goto pc+1",
		},
		{
			"conditional jump, 32 bit",
			asm.Instruction{
				OpCode: asm.OpCode(asm.Jump32Class).SetJumpOp(asm.JNE).SetSource(asm.ImmSource),
				Dst:    asm.R1, Constant: 5, Offset: 2,
			},
			"(56) if w1 != 0x5 goto pc+2",
		},
		{
			"unconditional jump",
			asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Ja), Offset: -2},
			"(05) goto pc-2",
		},
		{
			"long jump",
			asm.Instruction{OpCode: asm.OpCode(asm.Jump32Class).SetJumpOp(asm.Ja), Constant: 70000},
			"(06) gotol pc+70000",
		},
		{
			"may_goto",
			asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.JCOND), Src: asm.PseudoMayGoto, Offset: 4},
			"(e5) may_goto pc+4",
		},
		{"exit", asm.Return(), "(95) exit"},

		// An address-form call whose symbol could not be read - no privilege,
		// or kallsyms restricted - keeps the kernel's placeholder. Naming one
		// is TestFormatListing's job, since it takes a resolved symbol table.
		{
			"helper call by address, unresolved",
			asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Constant: 242800},
			"(85) call unknown#242800",
		},
		{
			// A call the verifier left as a plain helper id needs no symbols.
			"helper call by id",
			asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Constant: 35},
			"(85) call bpf_get_current_task#35",
		},
		{
			// What a tail call becomes on its way out of the kernel.
			"tail call",
			asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Constant: 12},
			"(85) call bpf_tail_call#12",
		},
		{
			"bpf-to-bpf call",
			asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoCall, Offset: 6},
			"(85) call pc+6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatInstruction(tt.ins, nil); got != tt.want {
				t.Errorf("formatInstruction() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFormatListing pins the whole shape of a dump against real bpftool output:
// the prologue of ig_execve_e, line for line as `bpftool prog dump xlated`
// printed it. Note the jump from 9 to 11 - the map load is double wide - and
// that instruction 0 carries both a BTF function and a symbol, the signature
// being what bpftool prints when it has the choice.
func TestFormatListing(t *testing.T) {
	execveEnter := &btf.Func{
		Name: "ig_execve_e",
		Type: &btf.FuncProto{
			Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
			Params: []btf.FuncParam{{
				Name: "ctx",
				Type: &btf.Pointer{Target: &btf.Struct{Name: "syscall_trace_enter"}},
			}},
		},
	}

	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R8, asm.R1), execveEnter).
			WithSymbol("ig_execve_e").
			WithSource(asm.Comment("int ig_execve_e(struct syscall_trace_enter *ctx)")),
		asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Constant: 242800}.
			WithSource(asm.Comment("uid_t uid = (u32)bpf_get_current_uid_gid();")),
		asm.LoadMem(asm.R1, asm.R8, 24, asm.DWord).
			WithSource(asm.Comment("const char **args = (const char **)(ctx->args[1]);")),
		asm.StoreMem(asm.R10, -32, asm.R1, asm.DWord).
			WithSource(asm.Comment("pid_tgid = bpf_get_current_pid_tgid();")),
		asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Constant: 242320},
		asm.Mov.Reg(asm.R9, asm.R0),
		asm.StoreMem(asm.R10, -4, asm.R9, asm.Word).
			WithSource(asm.Comment("pid = (u32)pid_tgid;")),
		asm.Mov.Reg(asm.R2, asm.R10),
		// A line info record whose source line is blank: bpftool prints the
		// comment marker anyway, and so do we.
		asm.Add.Imm(asm.R2, -4).WithSource(asm.Comment("")),
		asm.LoadMapPtr(asm.R1, 422).
			WithSource(asm.Comment("if (bpf_map_update_elem(&exec_args, &pid, &empty_record, 0))")),
		asm.Return(),
	}

	callNames := map[int32]string{
		242800: "bpf_get_current_uid_gid",
		242320: "bpf_get_current_pid_tgid",
	}

	want := []string{
		"int ig_execve_e(struct syscall_trace_enter * ctx):",
		"; int ig_execve_e(struct syscall_trace_enter *ctx)",
		"   0: (bf) r8 = r1",
		"; uid_t uid = (u32)bpf_get_current_uid_gid();",
		"   1: (85) call bpf_get_current_uid_gid#242800",
		"; const char **args = (const char **)(ctx->args[1]);",
		"   2: (79) r1 = *(u64 *)(r8 +24)",
		"; pid_tgid = bpf_get_current_pid_tgid();",
		"   3: (7b) *(u64 *)(r10 -32) = r1",
		"   4: (85) call bpf_get_current_pid_tgid#242320",
		"   5: (bf) r9 = r0",
		"; pid = (u32)pid_tgid;",
		"   6: (63) *(u32 *)(r10 -4) = r9",
		"   7: (bf) r2 = r10",
		"; ",
		"   8: (07) r2 += -4",
		"; if (bpf_map_update_elem(&exec_args, &pid, &empty_record, 0))",
		"   9: (18) r1 = map[id:422]",
		"  11: (95) exit",
	}

	got := formatListing(insns, callNames)
	if len(got) != len(want) {
		t.Fatalf("formatListing() produced %d lines, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRawOpcodeMatchesWire checks the assumption the "(bf)" column rests on:
// that the low byte of cilium's OpCode is the opcode as it sits in the
// instruction stream, with the flags it lifts into the higher bits staying out
// of the way. If a future cilium changes that encoding, the hex column would
// otherwise go quietly wrong.
func TestRawOpcodeMatchesWire(t *testing.T) {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R8, asm.R1),
		asm.SDiv.Reg(asm.R1, asm.R2),
		asm.MovSX32.Reg(asm.R1, asm.R2),
		asm.BSwap(asm.R1, asm.DWord),
		asm.HostTo(asm.BE, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R8, 24, asm.DWord),
		asm.LoadMemSX(asm.R1, asm.R2, 8, asm.Word),
		asm.StoreMem(asm.R10, -32, asm.R1, asm.DWord),
		asm.StoreImm(asm.R10, -8, 5, asm.Word),
		asm.StoreXAdd(asm.R1, asm.R2, asm.DWord),
		asm.FetchAdd.Mem(asm.R1, asm.R2, asm.Word, 4),
		asm.CmpXchg.Mem(asm.R1, asm.R2, asm.DWord, 0),
		asm.LoadMapPtr(asm.R1, 422),
		asm.LoadAbs(12, asm.Half),
		asm.Return(),
	}

	for _, ins := range insns {
		var buf bytes.Buffer
		if _, err := ins.Marshal(&buf, binary.LittleEndian); err != nil {
			t.Fatalf("marshal %v: %v", ins, err)
		}
		wire := buf.Bytes()[0]
		if got := byte(ins.OpCode); got != wire {
			t.Errorf("%v: OpCode low byte = %#02x, wire opcode = %#02x", ins, got, wire)
		}
	}
}

// TestFuncSignature covers the C declarations bpftool renders from BTF. Every
// type carries a trailing space, which is what separates it from the name it
// declares - and what bpftool leaves dangling when a parameter has no name.
func TestFuncSignature(t *testing.T) {
	intType := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	u32 := &btf.Int{Name: "unsigned int", Size: 4}

	tests := []struct {
		name string
		fn   *btf.Func
		want string
	}{
		{
			"pointer to struct",
			&btf.Func{Name: "ig_execve_e", Type: &btf.FuncProto{
				Return: intType,
				Params: []btf.FuncParam{{
					Name: "ctx",
					Type: &btf.Pointer{Target: &btf.Struct{Name: "syscall_trace_enter"}},
				}},
			}},
			"int ig_execve_e(struct syscall_trace_enter * ctx)",
		},
		{
			"no parameters",
			&btf.Func{Name: "tick", Type: &btf.FuncProto{Return: (*btf.Void)(nil)}},
			"void tick()",
		},
		{
			"several parameters",
			&btf.Func{Name: "add", Type: &btf.FuncProto{
				Return: u32,
				Params: []btf.FuncParam{{Name: "a", Type: u32}, {Name: "b", Type: intType}},
			}},
			"unsigned int add(unsigned int a, int b)",
		},
		{
			"qualifiers and typedefs",
			&btf.Func{Name: "put", Type: &btf.FuncProto{
				Return: &btf.Typedef{Name: "ssize_t", Type: intType},
				Params: []btf.FuncParam{{
					Name: "buf",
					Type: &btf.Pointer{Target: &btf.Const{Type: &btf.Int{Name: "char", Size: 1, Encoding: btf.Char}}},
				}},
			}},
			"ssize_t put(const char * buf)",
		},
		{
			"pointer to pointer, and a forward-declared type",
			&btf.Func{Name: "walk", Type: &btf.FuncProto{
				Return: (*btf.Void)(nil),
				Params: []btf.FuncParam{
					{Name: "argv", Type: &btf.Pointer{Target: &btf.Pointer{Target: intType}}},
					{Name: "sk", Type: &btf.Pointer{Target: &btf.Fwd{Name: "sock", Kind: btf.FwdStruct}}},
				},
			}},
			"void walk(int * * argv, struct sock * sk)",
		},
		{
			// A void parameter is BTF's variadic marker: a function taking no
			// arguments simply has none.
			"variadic",
			&btf.Func{Name: "printk", Type: &btf.FuncProto{
				Return: intType,
				Params: []btf.FuncParam{
					{Name: "fmt", Type: &btf.Pointer{Target: &btf.Int{Name: "char", Size: 1, Encoding: btf.Char}}},
					{Type: (*btf.Void)(nil)},
				},
			}},
			"int printk(char * fmt, ...)",
		},
		{
			"unnamed parameter keeps the type's trailing space, as bpftool does",
			&btf.Func{Name: "f", Type: &btf.FuncProto{
				Return: intType,
				Params: []btf.FuncParam{{Type: intType}},
			}},
			"int f(int )",
		},
		{
			"an array parameter",
			&btf.Func{Name: "sum", Type: &btf.FuncProto{
				Return: intType,
				Params: []btf.FuncParam{{Name: "xs", Type: &btf.Array{Type: intType, Nelems: 4}}},
			}},
			"int sum(int [4]xs)",
		},
		{
			// Nothing to render a signature from: fall back to the name.
			"no prototype",
			&btf.Func{Name: "mystery"},
			"mystery",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := funcSignature(tt.fn); got != tt.want {
				t.Errorf("funcSignature() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Without BTF - the agent lacking CAP_SYS_ADMIN, say - cilium leaves the
// program's name as a symbol and nothing else. bpftool prints no header at all
// there; a name is more use than nothing, so the fallback stands.
func TestFormatListingWithoutBTF(t *testing.T) {
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0).WithSymbol("trace_conn"),
		asm.Return(),
	}

	want := []string{
		"trace_conn:",
		"   0: (b7) r0 = 0",
		"   1: (95) exit",
	}

	got := formatListing(insns, nil)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("formatListing() =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
