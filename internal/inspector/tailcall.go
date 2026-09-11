package inspector

// Finding a program's tail calls in its own instructions, so the UI can say
// which program calls which.
//
// Everything else the node exposes stops one step short of that. A program
// array's slots name every program the table can reach; a program's map_ids
// names the tables it can jump through. Put together they say "this program may
// call any of these", which is as far as `bpftool prog show` and `map dump` can
// take it. The instructions are where the missing half is: a tail call is three
// of them, emitted together,
//
//	r2 = map[id:18723]     the program array
//	r3 = 3                 the slot, when the index is a constant
//	call bpf_tail_call#12
//
// and the first and second name one target between them.
//
// Both halves are there only because the kernel puts them there when preparing
// a program for dumping (bpf_insn_prepare_dump): it substitutes the map's id
// for the address the program holds, and rewrites the BPF_JMP|BPF_TAIL_CALL
// opcode back into a call to helper 12. Neither survives without the privilege
// an xlated dump needs anyway, so this reads what DumpProgram already has and
// asks the kernel for nothing more.
//
// The index does not have to be a constant - a program that picks its next
// stage at runtime computes it - and then the site names its table alone, which
// is what the caller already knew.

import (
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// TailCall is one bpf_tail_call site. ProgID is the program in the selected
// slot at the moment of the dump - live state, not part of the program - and is
// 0 when the index is computed, the slot is empty, or the map is gone.
type TailCall struct {
	Site     uint32 // instruction offset, in the numbering the listing prints
	MapID    uint32
	Index    uint32
	HasIndex bool
	ProgID   uint32
}

// maxTailCallScan bounds how far back from a call its arguments are looked for.
// The three instructions are emitted together, so an operand further back than
// this is one the stop conditions below did not catch - the least trustworthy
// kind of answer, and not worth the walk.
const maxTailCallScan = 64

// tailCalls returns the tail call sites of a program, target unresolved. A site
// whose program array cannot be read off the instructions is left out rather
// than reported without one: the table is the whole of what a site says, so a
// site without it says nothing the caller can use.
func tailCalls(insns asm.Instructions) []TailCall {
	list, targets := indexInsns(insns)
	var out []TailCall
	for i, at := range list {
		if !isTailCall(*at.ins) {
			continue
		}
		if targets[at.off] {
			// Something jumps straight at the call, so what falls into it is
			// one path of several and its operands are not the whole answer.
			continue
		}
		tc := TailCall{Site: uint32(at.off)}
		scanOperands(list[:i], targets, &tc)
		if tc.MapID == 0 {
			continue
		}
		out = append(out, tc)
	}
	return out
}

// insnAt is an instruction with the offset the listing gives it, which is not
// its index in the slice: a wide load takes two.
type insnAt struct {
	off asm.RawInstructionOffset
	ins *asm.Instruction
}

// indexInsns lays the instructions out by offset and collects the offsets a
// jump in this program can land on.
func indexInsns(insns asm.Instructions) ([]insnAt, map[asm.RawInstructionOffset]bool) {
	var list []insnAt
	targets := map[asm.RawInstructionOffset]bool{}
	iter := insns.Iterate()
	for iter.Next() {
		list = append(list, insnAt{off: iter.Offset, ins: iter.Ins})
		if t, ok := jumpTarget(*iter.Ins, iter.Offset); ok {
			targets[t] = true
		}
	}
	return list, targets
}

// jumpTarget is where a jump lands, in the same offsets. A call is not a jump
// within the program - a helper leaves and comes back, and a bpf-to-bpf call
// lands in a function of its own - and an exit lands nowhere.
func jumpTarget(ins asm.Instruction, off asm.RawInstructionOffset) (asm.RawInstructionOffset, bool) {
	if !ins.OpCode.Class().IsJump() {
		return 0, false
	}
	op := ins.OpCode.JumpOp()
	if op == asm.Call || op == asm.Exit {
		return 0, false
	}
	rel := int64(ins.Offset)
	if op == asm.Ja && ins.OpCode.Class() == asm.Jump32Class {
		rel = int64(int32(ins.Constant)) // gotol, whose range is imm rather than off
	}
	return asm.RawInstructionOffset(int64(off) + 1 + rel), true
}

// isTailCall reports whether ins is a call to bpf_tail_call. Src distinguishes
// the three kinds of call sharing one opcode: a helper leaves it at r0, a
// bpf-to-bpf call sets BPF_PSEUDO_CALL and a kfunc BPF_PSEUDO_KFUNC_CALL, and
// the latter two carry something other than a helper id in imm.
func isTailCall(ins asm.Instruction) bool {
	return ins.OpCode.Class().IsJump() && ins.OpCode.JumpOp() == asm.Call &&
		ins.Src == asm.R0 && int32(ins.Constant) == int32(asm.FnTailCall)
}

// scanOperands walks back from a tail call for the registers it takes its
// arguments in - r2 the program array, r3 the slot - and gives up on a register
// where a value read further back could not be the one the call sees:
//
//   - at any call, which clobbers r1-r5;
//   - at an unconditional jump, past which the instructions are on another path
//     (a conditional one is fine: this call is on its fall-through);
//   - at an instruction something can jump to, since another path can arrive
//     there carrying other values;
//   - at anything writing the register itself, which is then a value this
//     cannot read - a computed index, or a map pointer passed in.
//
// Each of those leaves an operand unread rather than guessed: a missing edge is
// a gap in the diagram, a wrong one is a lie about what the program does.
func scanOperands(before []insnAt, targets map[asm.RawInstructionOffset]bool, tc *TailCall) {
	gotMap, gotIndex := false, false
	for i := len(before) - 1; i >= 0 && len(before)-i <= maxTailCallScan; i-- {
		ins := before[i].ins
		if stopsScan(*ins) {
			return
		}
		switch {
		case gotMap:
		case ins.IsLoadFromMap() && ins.Dst == asm.R2 && ins.Src == asm.PseudoMapFD:
			// The kernel put the map's id in the low half of the imm pair.
			tc.MapID, gotMap = uint32(ins.Constant), true
		case writesReg(*ins, asm.R2):
			gotMap = true
		}
		switch {
		case gotIndex:
		case isMovImm(*ins, asm.R3):
			tc.Index, tc.HasIndex, gotIndex = uint32(int32(ins.Constant)), true, true
		case writesReg(*ins, asm.R3):
			gotIndex = true
		}
		if gotMap && gotIndex {
			return
		}
		if targets[before[i].off] {
			return
		}
	}
}

// stopsScan reports whether the backward walk must stop before ins.
func stopsScan(ins asm.Instruction) bool {
	if !ins.OpCode.Class().IsJump() {
		return false
	}
	switch ins.OpCode.JumpOp() {
	case asm.Call, asm.Exit, asm.Ja:
		return true
	}
	return false
}

// isMovImm reports whether ins loads a constant into r. Both widths count: the
// index is a 32-bit value either way, so "w3 = 3" selects the slot "r3 = 3"
// does.
func isMovImm(ins asm.Instruction, r asm.Register) bool {
	return ins.OpCode.Class().IsALU() && ins.OpCode.ALUOp() == asm.Mov &&
		ins.OpCode.Source() == asm.ImmSource && ins.Dst == r
}

// writesReg reports whether ins may leave a new value in r. It is deliberately
// generous: a false positive gives up on an operand, a false negative reads a
// stale one and names the wrong program.
func writesReg(ins asm.Instruction, r asm.Register) bool {
	switch cls := ins.OpCode.Class(); {
	case cls == asm.LdClass &&
		(ins.OpCode.Mode() == asm.AbsMode || ins.OpCode.Mode() == asm.IndMode):
		// The legacy packet loads land in r0 and clobber r1-r5 along with it.
		return true
	case cls.IsALU(), cls == asm.LdClass, cls == asm.LdXClass:
		return ins.Dst == r
	case cls == asm.StXClass && ins.OpCode.Mode() == asm.AtomicMode:
		// A fetching atomic leaves the old value in its source register, and a
		// compare-and-exchange in r0.
		return ins.Src == r || r == asm.R0
	default:
		return false
	}
}

// resolveTailCallTargets fills in the program each site jumps to by reading the
// slot its index selects. A site whose index is computed selects no one slot,
// and keeps none.
func resolveTailCallTargets(calls []TailCall) {
	for i := range calls {
		if calls[i].HasIndex {
			calls[i].ProgID = progArraySlot(calls[i].MapID, calls[i].Index)
		}
	}
}

// progArraySlot reads one slot of a program array as the id of the program in
// it - the same host-order u32 fdArrayID decodes for a dump - or 0 when there is
// nothing there to read. Best-effort throughout: the map may be gone, or of
// another type entirely if the instructions were misread, and neither is worth
// failing a dump over.
func progArraySlot(mapID, index uint32) uint32 {
	m, err := ebpf.NewMapFromID(ebpf.MapID(mapID))
	if err != nil {
		return 0
	}
	defer m.Close()
	if m.Type() != ebpf.ProgramArray {
		return 0
	}
	key := make([]byte, 4)
	binary.NativeEndian.PutUint32(key, index)
	value, err := m.LookupBytes(key)
	if err != nil || value == nil {
		return 0 // out of range, or an empty slot: cilium reads one back as nothing
	}
	return fdArrayID(value)
}
