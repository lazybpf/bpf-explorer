package inspector

// A printer for xlated instructions that matches `bpftool prog dump xlated`
// line for line, so a dump in the UI can be diffed against bpftool's.
//
// cilium/ebpf's own Instructions formatter prints the assembler DSL it uses to
// *build* programs ("MovReg dst: r8 src: r1"). bpftool prints the kernel's
// disassembler - kernel/bpf/disasm.c, vendored into tools/bpf/bpftool - wrapped
// in its own offset column. The format strings below are that disassembler's,
// verbatim, with the C verbs translated to Go ones; the branch order is its
// order too. Where the kernel reads a flag out of an instruction's off or imm
// field, cilium has already lifted it into the OpCode while decoding, so we
// read it back from there - noted at each such site.
//
// The two pieces of a dump that the instruction stream alone cannot supply -
// the name behind a call, and the signature in a function header - come from
// kallsyms.go and from BTF metadata cilium attaches to the instructions. Both
// degrade rather than fail: a call whose symbol cannot be read prints as
// `call unknown#242800`, and a function with no BTF prints as a bare name.
// bpftool goes quiet in the second case, printing no header at all; a name is
// more use than nothing.
//
// One difference left: for a call to another BPF function, bpftool names the
// subprogram it lands in - `call pc+6#handle_event` - by reading the JIT's
// kernel symbols out of the program's info. We print the offset alone.

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// addrSpaceCast is BPF_ADDR_SPACE_CAST, the value in a MOV's off field that
// marks it as an address space cast. Unlike the sign-extending MOVs, cilium
// does not fold this one into the ALUOp, so it stays readable in ins.Offset.
const addrSpaceCast = 1

// bpf_alu_string, plus the two entries the kernel keeps in its separate
// bpf_alu_sign_string table. Neg and Swap are absent because the kernel prints
// them from their own branches, and so do we.
var aluStrings = map[asm.ALUOp]string{
	asm.Add:  "+=",
	asm.Sub:  "-=",
	asm.Mul:  "*=",
	asm.Div:  "/=",
	asm.SDiv: "s/=",
	asm.Or:   "|=",
	asm.And:  "&=",
	asm.LSh:  "<<=",
	asm.RSh:  ">>=",
	asm.Mod:  "%=",
	asm.SMod: "s%=",
	asm.Xor:  "^=",
	asm.Mov:  "=",
	asm.ArSh: "s>>=",
	// A sign-extending MOV prints as a plain "=" followed by a cast on the
	// source register; see movSXStrings.
	asm.MovSX8:  "=",
	asm.MovSX16: "=",
	asm.MovSX32: "=",
}

// bpf_movsx_string.
var movSXStrings = map[asm.ALUOp]string{
	asm.MovSX8:  "(s8)",
	asm.MovSX16: "(s16)",
	asm.MovSX32: "(s32)",
}

// bpf_ldst_string: the C type the kernel casts through for a given access size.
var sizeStrings = map[asm.Size]string{
	asm.Byte:  "u8",
	asm.Half:  "u16",
	asm.Word:  "u32",
	asm.DWord: "u64",
}

// bpf_ldsx_string, the same for sign-extending loads. There is no 64-bit entry:
// a sign-extending load of a double word would extend nothing.
var sizeSXStrings = map[asm.Size]string{
	asm.Byte: "s8",
	asm.Half: "s16",
	asm.Word: "s32",
}

// bpf_jmp_string, minus Ja, Call and Exit, which have their own branches.
var jumpStrings = map[asm.JumpOp]string{
	asm.JEq:  "==",
	asm.JGT:  ">",
	asm.JLT:  "<",
	asm.JGE:  ">=",
	asm.JLE:  "<=",
	asm.JSet: "&",
	asm.JNE:  "!=",
	asm.JSGT: "s>",
	asm.JSLT: "s<",
	asm.JSGE: "s>=",
	asm.JSLE: "s<=",
}

// The two ways the kernel names an atomic's operation: bpf_alu_string for the
// plain lock forms, bpf_atomic_alu_string for the fetching ones.
var atomicLockStrings = map[asm.AtomicOp]string{
	asm.AddAtomic: "+=",
	asm.AndAtomic: "&=",
	asm.OrAtomic:  "|=",
	asm.XorAtomic: "^=",
}

var atomicFetchStrings = map[asm.AtomicOp]string{
	asm.FetchAdd: "add",
	asm.FetchAnd: "and",
	asm.FetchOr:  "or",
	asm.FetchXor: "xor",
}

// formatListing renders a program's instructions as bpftool's plain xlated
// dump: a header line per function, a "; " comment for each source line BTF has
// info for, and one "%4d: (%02x) ..." line per instruction. Offsets are raw
// instruction offsets, so a double-wide load makes the next line jump by two -
// the same numbering bpftool prints. callNames comes from resolveCalls and may
// be nil.
func formatListing(insns asm.Instructions, callNames map[int32]string) []string {
	var lines []string
	iter := insns.Iterate()
	for iter.Next() {
		// Each function's BTF is attached to the instruction it starts at,
		// which is where the signature comes from. The symbol is the fallback
		// for a program whose BTF we could not read: cilium puts the program's
		// name there.
		if fn := btf.FuncMetadata(iter.Ins); fn != nil {
			lines = append(lines, funcSignature(fn)+":")
		} else if sym := iter.Ins.Symbol(); sym != "" {
			lines = append(lines, sym+":")
		}
		if src := iter.Ins.Source(); src != nil {
			// bpftool only left-trims the line, and prints the comment even
			// when nothing is left of it. That is where the bare "; " lines in
			// its output come from, so keep them: they are anchors when diffing.
			lines = append(lines, "; "+strings.TrimLeftFunc(src.String(), unicode.IsSpace))
		}
		lines = append(lines, fmt.Sprintf("%4d: %s", iter.Offset, formatInstruction(*iter.Ins, callNames)))
	}
	return lines
}

// formatInstruction renders one instruction the way print_bpf_insn does: the
// raw opcode byte in parentheses, then the operation in C-like syntax.
func formatInstruction(ins asm.Instruction, callNames map[int32]string) string {
	// The low byte of cilium's OpCode is the opcode as it sits in the
	// instruction stream; the higher bits hold flags cilium lifted out of the
	// off and imm fields while decoding, which never reach the wire.
	raw := byte(ins.OpCode)

	switch cls := ins.OpCode.Class(); {
	case cls.IsALU():
		return formatALU(ins, raw, cls)
	case cls == asm.StXClass:
		return formatStX(ins, raw)
	case cls == asm.StClass:
		return formatSt(ins, raw)
	case cls == asm.LdXClass:
		return formatLdX(ins, raw)
	case cls == asm.LdClass:
		return formatLd(ins, raw)
	case cls.IsJump():
		return formatJump(ins, raw, cls, callNames)
	default:
		return fmt.Sprintf("(%02x) %v", raw, cls)
	}
}

func formatALU(ins asm.Instruction, raw byte, cls asm.Class) string {
	op := ins.OpCode.ALUOp()

	switch {
	case op == asm.Swap:
		// The 64-bit class is the unconditional bswap; the 32-bit one converts
		// to a named endianness. Both take their width from imm rather than
		// from the opcode's size bits, and both print r-registers whatever the
		// class.
		if cls == asm.ALU64Class {
			return fmt.Sprintf("(%02x) %s = bswap%d %s", raw, reg(ins.Dst), ins.Constant, reg(ins.Dst))
		}
		to := "le"
		if ins.OpCode.Endianness() == asm.BE {
			to = "be"
		}
		return fmt.Sprintf("(%02x) %s = %s%d %s", raw, reg(ins.Dst), to, ins.Constant, reg(ins.Dst))

	case op == asm.Neg:
		return fmt.Sprintf("(%02x) %s = -%s", raw, regFor(cls, ins.Dst), regFor(cls, ins.Dst))

	case op == asm.Mov && cls == asm.ALU64Class &&
		ins.OpCode.Source() == asm.RegSource && ins.Offset == addrSpaceCast:
		// Arena pointer casts. imm carries the destination address space in its
		// high half and the source in its low half, except for the per-CPU
		// form, which the kernel encodes as a bare 1 and prints differently.
		if ins.Constant == 1 {
			return fmt.Sprintf("(%02x) %s = &(void __percpu *)(%s)", raw, reg(ins.Dst), reg(ins.Src))
		}
		return fmt.Sprintf("(%02x) %s = addr_space_cast(%s, %d, %d)",
			raw, reg(ins.Dst), reg(ins.Src), uint32(ins.Constant)>>16, uint32(ins.Constant)&0xffff)

	case ins.OpCode.Source() == asm.RegSource:
		return fmt.Sprintf("(%02x) %s %s %s%s",
			raw, regFor(cls, ins.Dst), aluString(op), movSXStrings[op], regFor(cls, ins.Src))

	default:
		return fmt.Sprintf("(%02x) %s %s %d", raw, regFor(cls, ins.Dst), aluString(op), int32(ins.Constant))
	}
}

func formatStX(ins asm.Instruction, raw byte) string {
	switch ins.OpCode.Mode() {
	case asm.MemMode:
		return fmt.Sprintf("(%02x) *(%s *)(%s %+d) = %s",
			raw, sizeStrings[ins.OpCode.Size()], reg(ins.Dst), ins.Offset, reg(ins.Src))
	case asm.AtomicMode:
		return formatAtomic(ins, raw)
	default:
		return fmt.Sprintf("BUG_%02x", raw)
	}
}

func formatAtomic(ins asm.Instruction, raw byte) string {
	op := ins.OpCode.AtomicOp()
	size := sizeStrings[ins.OpCode.Size()]
	// The kernel names the 64-bit atomics atomic64_*, the 32-bit ones atomic_*.
	width := ""
	if ins.OpCode.Size() == asm.DWord {
		width = "64"
	}

	switch {
	case atomicLockStrings[op] != "":
		return fmt.Sprintf("(%02x) lock *(%s *)(%s %+d) %s %s",
			raw, size, reg(ins.Dst), ins.Offset, atomicLockStrings[op], reg(ins.Src))
	case atomicFetchStrings[op] != "":
		return fmt.Sprintf("(%02x) %s = atomic%s_fetch_%s((%s *)(%s %+d), %s)",
			raw, reg(ins.Src), width, atomicFetchStrings[op], size, reg(ins.Dst), ins.Offset, reg(ins.Src))
	case op == asm.CmpXchg:
		return fmt.Sprintf("(%02x) r0 = atomic%s_cmpxchg((%s *)(%s %+d), r0, %s)",
			raw, width, size, reg(ins.Dst), ins.Offset, reg(ins.Src))
	case op == asm.Xchg:
		return fmt.Sprintf("(%02x) %s = atomic%s_xchg((%s *)(%s %+d), %s)",
			raw, reg(ins.Src), width, size, reg(ins.Dst), ins.Offset, reg(ins.Src))
	default:
		// Load-acquire and store-release, added in 6.15, land here: bpftool
		// v7.5 does not know them either and prints the same.
		return fmt.Sprintf("BUG_%02x", raw)
	}
}

func formatSt(ins asm.Instruction, raw byte) string {
	switch ins.OpCode.Mode() {
	case asm.MemMode:
		return fmt.Sprintf("(%02x) *(%s *)(%s %+d) = %d",
			raw, sizeStrings[ins.OpCode.Size()], reg(ins.Dst), ins.Offset, int32(ins.Constant))
	case asm.AtomicMode:
		// BPF_NOSPEC shares its mode bits with BPF_ATOMIC; the store class is
		// what tells the two apart. The verifier inserts it as a barrier.
		return fmt.Sprintf("(%02x) nospec", raw)
	default:
		return fmt.Sprintf("BUG_st_%02x", raw)
	}
}

func formatLdX(ins asm.Instruction, raw byte) string {
	mode := ins.OpCode.Mode()
	if mode != asm.MemMode && mode != asm.MemSXMode {
		return fmt.Sprintf("BUG_ldx_%02x", raw)
	}
	size := sizeStrings[ins.OpCode.Size()]
	if mode == asm.MemSXMode {
		size = sizeSXStrings[ins.OpCode.Size()]
	}
	return fmt.Sprintf("(%02x) %s = *(%s *)(%s %+d)", raw, reg(ins.Dst), size, reg(ins.Src), ins.Offset)
}

func formatLd(ins asm.Instruction, raw byte) string {
	size := sizeStrings[ins.OpCode.Size()]
	switch ins.OpCode.Mode() {
	case asm.AbsMode:
		// The legacy cBPF-style packet loads, still emitted for socket filters.
		return fmt.Sprintf("(%02x) r0 = *(%s *)skb[%d]", raw, size, int32(ins.Constant))
	case asm.IndMode:
		return fmt.Sprintf("(%02x) r0 = *(%s *)skb[%s + %d]", raw, size, reg(ins.Src), int32(ins.Constant))
	case asm.ImmMode:
		if ins.OpCode.Size() != asm.DWord {
			return fmt.Sprintf("BUG_ld_%02x", raw)
		}
		return fmt.Sprintf("(%02x) %s = %s", raw, reg(ins.Dst), immString(ins))
	default:
		return fmt.Sprintf("BUG_ld_%02x", raw)
	}
}

// immString renders the value of a double-wide immediate load, which is rarely
// a plain number: the src register says what kind of pointer it is. This one is
// bpftool's print_imm rather than the kernel's, which prints the raw value and
// leaves it to its caller to substitute something friendlier.
func immString(ins asm.Instruction) string {
	// The load's two halves carry 32 bits of imm each; cilium joins them into
	// Constant, low half first.
	lo, hi := uint32(ins.Constant), uint32(uint64(ins.Constant)>>32)

	switch ins.Src {
	case asm.PseudoMapFD:
		// Not a file descriptor by the time we read it back: the kernel
		// substitutes the map's id when preparing a program for dumping.
		return fmt.Sprintf("map[id:%d]", lo)
	case asm.PseudoMapValue:
		return fmt.Sprintf("map[id:%d][0]+%d", lo, hi)
	case asm.PseudoFunc:
		return fmt.Sprintf("subprog[%+d]", int32(lo))
	case pseudoMapIdxValue:
		return fmt.Sprintf("map[idx:%d]+%d", lo, hi)
	default:
		return fmt.Sprintf("0x%x", uint64(ins.Constant))
	}
}

// pseudoMapIdxValue is BPF_PSEUDO_MAP_IDX_VALUE, which cilium has no name for.
// It only appears in unloaded ELF objects, never in a program read back from
// the kernel, but bpftool prints it and the cost of matching is a line.
const pseudoMapIdxValue = asm.Register(6)

func formatJump(ins asm.Instruction, raw byte, cls asm.Class, callNames map[int32]string) string {
	op := ins.OpCode.JumpOp()

	switch {
	case op == asm.Call && ins.Src == asm.PseudoCall:
		// A call to another BPF function. The kernel stores the target as a
		// pc-relative offset in off, leaving imm to the JIT.
		return fmt.Sprintf("(%02x) call pc%+d", raw, ins.Offset)

	case op == asm.Call:
		// A helper or kfunc call, named from kallsyms when its imm is an
		// address, and from the helper table when the verifier left it as an
		// id. "unknown" is the kernel's own placeholder for a call it cannot
		// name at all.
		imm := int32(ins.Constant)
		name := callNames[imm]
		if name == "" {
			name = helperName(imm)
		}
		if name == "" {
			name = "unknown"
		}
		return fmt.Sprintf("(%02x) call %s#%d", raw, name, imm)

	case op == asm.Ja && cls == asm.Jump32Class:
		// The long jump, whose range is imm rather than off's 16 bits.
		return fmt.Sprintf("(%02x) gotol pc%+d", raw, int32(ins.Constant))

	case op == asm.Ja:
		return fmt.Sprintf("(%02x) goto pc%+d", raw, ins.Offset)

	case op == asm.JCOND && ins.Src == asm.PseudoMayGoto:
		return fmt.Sprintf("(%02x) may_goto pc%+d", raw, ins.Offset)

	case op == asm.Exit:
		return fmt.Sprintf("(%02x) exit", raw)

	case ins.OpCode.Source() == asm.RegSource:
		return fmt.Sprintf("(%02x) if %s %s %s goto pc%+d",
			raw, regFor(cls, ins.Dst), jumpString(op), regFor(cls, ins.Src), ins.Offset)

	default:
		// The kernel prints the comparand as unsigned hex whatever the
		// signedness of the comparison itself.
		return fmt.Sprintf("(%02x) if %s %s 0x%x goto pc%+d",
			raw, regFor(cls, ins.Dst), jumpString(op), uint32(ins.Constant), ins.Offset)
	}
}

// maxTypeDepth bounds how far cType will follow a type, since the BTF it walks
// arrived with a program someone else loaded. Real declarations nest a handful
// of levels; this only stops a malformed one from looping.
const maxTypeDepth = 16

// funcSignature renders a function's BTF as the C declaration bpftool prints
// above its instructions - "int ig_execve_e(struct syscall_trace_enter * ctx)".
func funcSignature(fn *btf.Func) string {
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return fn.Name
	}

	var sb strings.Builder
	// Every type ends in a space, so the name follows straight on.
	sb.WriteString(cType(proto.Return, 0))
	sb.WriteString(fn.Name)
	sb.WriteString("(")
	for i, p := range proto.Params {
		if i > 0 {
			sb.WriteString(", ")
		}
		// A parameter of type void is C's "...": a function of no arguments
		// has no parameters at all in BTF, not one void parameter.
		if _, ok := p.Type.(*btf.Void); ok {
			sb.WriteString("...")
			continue
		}
		sb.WriteString(cType(p.Type, 0))
		sb.WriteString(p.Name)
	}
	sb.WriteString(")")
	return sb.String()
}

// cType renders a BTF type as bpftool's btf_dumper_type_only does, down to the
// trailing space every type carries and the space it leaves in front of a
// pointer's star.
func cType(t btf.Type, depth int) string {
	if depth > maxTypeDepth {
		return "? "
	}

	switch t := t.(type) {
	case nil, *btf.Void:
		return "void "
	case *btf.Int:
		return t.Name + " "
	case *btf.Typedef:
		return t.Name + " "
	case *btf.Float:
		return t.Name + " "
	case *btf.Struct:
		return "struct " + t.Name + " "
	case *btf.Union:
		return "union " + t.Name + " "
	case *btf.Enum:
		return "enum " + t.Name + " "
	case *btf.Fwd:
		// A type only declared, never defined: its kind is all BTF knows.
		return t.Kind.String() + " " + t.Name + " "
	case *btf.Pointer:
		return cType(t.Target, depth+1) + "* "
	case *btf.Array:
		return cType(t.Type, depth+1) + "[" + strconv.FormatUint(uint64(t.Nelems), 10) + "]"
	case *btf.Const:
		return "const " + cType(t.Type, depth+1)
	case *btf.Volatile:
		return "volatile " + cType(t.Type, depth+1)
	case *btf.Restrict:
		return "restrict " + cType(t.Type, depth+1)
	case *btf.FuncProto:
		// The proto behind a function pointer. Like bpftool, print the return
		// type and the parameter types without C's declarator parentheses.
		var sb strings.Builder
		sb.WriteString(cType(t.Return, depth+1))
		sb.WriteString("(")
		for i, p := range t.Params {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(cType(p.Type, depth+1))
			sb.WriteString(p.Name)
		}
		sb.WriteString(")")
		return sb.String()
	default:
		return t.TypeName() + " "
	}
}

// reg names a register rN, with no special name for r10 - cilium's own
// Register.String calls it "rfp". Loads, stores and calls print registers this
// way whatever their class.
func reg(r asm.Register) string {
	return "r" + strconv.Itoa(int(r))
}

// regFor is reg for the ALU and jump classes, which print wN for the operations
// that work on the low 32 bits.
func regFor(cls asm.Class, r asm.Register) string {
	if cls == asm.ALUClass || cls == asm.Jump32Class {
		return "w" + strconv.Itoa(int(r))
	}
	return reg(r)
}

// aluString and jumpString fall back to the numeric operation for an op the
// kernel has gained since these tables were written, so a new opcode reads as
// unknown rather than as a missing operator.
func aluString(op asm.ALUOp) string {
	if s, ok := aluStrings[op]; ok {
		return s
	}
	return fmt.Sprintf("alu(%#x)", uint16(op))
}

func jumpString(op asm.JumpOp) string {
	if s, ok := jumpStrings[op]; ok {
		return s
	}
	return fmt.Sprintf("jmp(%#x)", uint8(op))
}
