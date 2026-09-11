package inspector

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

// The three instructions a tail call is, as the kernel hands them back: the map
// load carrying an id rather than an fd, the slot, and helper 12.
func loadArray(id uint32) asm.Instruction { return asm.LoadMapPtr(asm.R2, int(id)) }
func slot(n int32) asm.Instruction        { return asm.Mov.Imm(asm.R3, n) }

// What a tail call looks like on its way out of the kernel: the opcode is
// rewritten to a call and imm to bpf_tail_call's helper id. helperCall is
// kallsyms_test.go's, which builds exactly that instruction.
func tailCallIns() asm.Instruction { return helperCall(12) }

func goto_(off int16) asm.Instruction {
	return asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Ja), Offset: off}
}
func jeq(off int16) asm.Instruction {
	return asm.Instruction{
		OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.JEq).SetSource(asm.ImmSource),
		Dst:    asm.R1, Offset: off,
	}
}

// TestTailCallsConstantIndex is the idiom the compiler emits for
// tail_call(ctx, &kprobe_calls, 3): the two operands then the call, and the
// site offset counting the map load as the two instructions it is.
func TestTailCallsConstantIndex(t *testing.T) {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R1, asm.R6),
		loadArray(18723),
		slot(3),
		tailCallIns(),
		asm.Return(),
	}
	got := tailCalls(insns)
	if len(got) != 1 {
		t.Fatalf("tailCalls = %+v, want one site", got)
	}
	want := TailCall{Site: 4, MapID: 18723, Index: 3, HasIndex: true}
	if got[0] != want {
		t.Errorf("tailCalls = %+v, want %+v", got[0], want)
	}
}

// TestTailCallsComputedIndex covers the other common shape: the program picks
// its next stage at runtime, so the site names its table and no slot. Worth
// keeping - the table is still the answer to which programs it may reach.
func TestTailCallsComputedIndex(t *testing.T) {
	insns := asm.Instructions{
		loadArray(18723),
		asm.Mov.Reg(asm.R3, asm.R7),
		tailCallIns(),
	}
	got := tailCalls(insns)
	if len(got) != 1 {
		t.Fatalf("tailCalls = %+v, want one site", got)
	}
	if got[0].MapID != 18723 || got[0].HasIndex {
		t.Errorf("tailCalls = %+v, want the table alone", got[0])
	}
}

// TestTailCallsStops covers the shapes where an operand read further back would
// be a value the call does not see. Each drops the operand rather than guessing
// it: a missing edge is a gap, a wrong one is a lie about the program.
func TestTailCallsStops(t *testing.T) {
	tests := []struct {
		name  string
		insns asm.Instructions
		want  []TailCall
	}{
		{
			// A helper call clobbers r1-r5, so neither operand survives it and
			// there is nothing left to say about the site.
			"call between the operands and the tail call",
			asm.Instructions{loadArray(18723), slot(3), helperCall(14), tailCallIns()},
			nil,
		},
		{
			// Something jumps into the middle of the sequence. The slot it
			// lands on is still the one every path sets, but the load above it
			// is on one path only, so the table goes unread and with it the
			// site: a slot of no table names nothing.
			"a jump into the middle of the sequence",
			asm.Instructions{
				jeq(2), // over the load, landing on the slot
				loadArray(18723),
				slot(3),
				tailCallIns(),
			},
			nil,
		},
		{
			// The same jump one instruction further, landing on the call
			// itself: both operands are then one path's out of several.
			"a jump target on the call",
			asm.Instructions{jeq(3), loadArray(18723), slot(3), tailCallIns()},
			nil,
		},
		{
			// Past an unconditional jump the instructions are not on this
			// call's path at all.
			"an unconditional jump between",
			asm.Instructions{loadArray(18723), slot(3), goto_(0), tailCallIns()},
			nil,
		},
		{
			// The map pointer came from somewhere this cannot read - passed in,
			// or picked between two tables - so the site names no table.
			"the array arrives in a register",
			asm.Instructions{asm.Mov.Reg(asm.R2, asm.R8), slot(3), tailCallIns()},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tailCalls(tt.insns)
			if len(got) != len(tt.want) {
				t.Fatalf("tailCalls = %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("tailCalls[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestTailCallsOnlyHelper12 checks the other two calls sharing the opcode are
// not read as tail calls: a bpf-to-bpf call carries an offset in imm and a
// kfunc a BTF id, either of which can be 12.
func TestTailCallsOnlyHelper12(t *testing.T) {
	for name, call := range map[string]asm.Instruction{
		"bpf-to-bpf call": {OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call),
			Src: asm.PseudoCall, Constant: 12},
		"kfunc call": {OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call),
			Src: asm.PseudoKfuncCall, Constant: 12},
		"another helper": helperCall(14),
	} {
		t.Run(name, func(t *testing.T) {
			insns := asm.Instructions{loadArray(18723), slot(3), call}
			if got := tailCalls(insns); len(got) != 0 {
				t.Errorf("tailCalls = %+v, want none", got)
			}
		})
	}
}

// TestTailCallsSeveralSites checks a program with a chain of them: each site
// reads its own operands, and the one nearest the call wins.
func TestTailCallsSeveralSites(t *testing.T) {
	insns := asm.Instructions{
		loadArray(18723),
		slot(3),
		tailCallIns(),
		loadArray(18723),
		slot(5),
		tailCallIns(),
		asm.Return(),
	}
	got := tailCalls(insns)
	if len(got) != 2 {
		t.Fatalf("tailCalls = %+v, want two sites", got)
	}
	if got[0].Index != 3 || got[1].Index != 5 {
		t.Errorf("tailCalls = %+v, want slots 3 then 5", got)
	}
	if got[0].Site != 3 || got[1].Site != 7 {
		t.Errorf("sites = %d, %d; want 3 and 7", got[0].Site, got[1].Site)
	}
}
