package inspector

// Naming a program's call targets, the way bpftool does it.
//
// The verifier rewrites most helper and kfunc calls' imm into an offset from
// __bpf_call_base, so what a dumped call usually carries is an address, not an
// id, and `call bpf_get_current_uid_gid#242800` only comes back by looking that
// address up in /proc/kallsyms. Reading real addresses there takes privilege:
// an unprivileged reader, or kernel.kptr_restrict, sees every address as zero.
// That is also how bpftool decides to give up - a __bpf_call_base of zero means
// the addresses are hidden.
//
// Not every call is rewritten, though. Some reach a dump with the plain helper
// id they were compiled with, where no address arithmetic can name them - a
// tail call, for one, which the kernel turns back into `call #12` on its way
// out. bpftool names those from the helper table it is built with, and
// helperName does the same, so `call #35` reads as bpf_get_current_task.

import (
	"bufio"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/cilium/ebpf/asm"
)

const kallsymsPath = "/proc/kallsyms"

// __bpf_call_base is fixed for as long as the kernel is up, so it is worth
// caching across dumps. Zero doubles as "not resolved yet" and "addresses are
// hidden", which is what we want: a later dump looks again, in case the agent
// gained privilege or kptr_restrict was relaxed. Looking again is a full walk
// of a few hundred thousand symbols, tens of milliseconds, which a dump only
// pays when it has calls to name.
var (
	callBaseMu   sync.Mutex
	callBaseAddr uint64
)

// resolveCalls names the helper and kfunc calls in insns, keyed by the imm each
// carries, for the disassembler to print. Returns nil when the symbols are
// unreadable, in which case the dump says so by printing the calls as unknown.
func resolveCalls(insns asm.Instructions) map[int32]string {
	if !slices.ContainsFunc(insns, resolvableCall) {
		return nil
	}
	base := bpfCallBase()
	if base == 0 {
		return nil
	}
	f, err := os.Open(kallsymsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	return callNames(insns, base, f)
}

// callNames resolves the call targets in insns against a kallsyms-formatted
// symbol table, given the address __bpf_call_base sits at.
func callNames(insns asm.Instructions, base uint64, syms io.Reader) map[int32]string {
	// Collect the addresses to look for first, so the symbol table is walked
	// once however many calls the program makes.
	wanted := make(map[uint64]int32)
	for _, ins := range insns {
		if !resolvableCall(ins) {
			continue
		}
		imm := int32(ins.Constant)
		// A helper can sit below __bpf_call_base, making imm negative; the
		// conversion through int64 keeps the subtraction that implies.
		wanted[base+uint64(int64(imm))] = imm
	}
	if len(wanted) == 0 {
		return nil
	}

	names := make(map[int32]string, len(wanted))
	scanSymbols(syms, func(addr uint64, name string) bool {
		imm, ok := wanted[addr]
		if !ok {
			return true
		}
		names[imm] = name
		delete(wanted, addr)
		// Kernels carry ~200k symbols, so stop as soon as every call is named.
		return len(wanted) > 0
	})
	return names
}

// helperName names a call that carries a helper id rather than an address, or
// returns "" if the id names no helper.
//
// cilium generates its BuiltinFunc constants from the same kernel macro that
// bpftool builds its helper table from, capitalising each underscore-separated
// word, so lowering the capitals back recovers the helper's real name. All 211
// of them round-trip to the names bpftool itself carries.
func helperName(imm int32) string {
	// Id zero is BPF_FUNC_unspec, which no program calls - but it is also what
	// the kernel writes over every call's imm when it will not show addresses,
	// and naming a redacted call would be worse than leaving it unknown.
	if imm <= 0 {
		return ""
	}
	fn := asm.BuiltinFunc(imm).String()
	if !strings.HasPrefix(fn, "Fn") {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("bpf")
	for _, r := range fn[len("Fn"):] {
		if unicode.IsUpper(r) {
			sb.WriteByte('_')
			r = unicode.ToLower(r)
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// resolvableCall reports whether ins calls something kallsyms can name: a
// helper or a kfunc, whose imm is an address. A call to another BPF function
// carries a pc-relative offset instead, which would name whatever happens to
// sit at that address.
func resolvableCall(ins asm.Instruction) bool {
	return ins.OpCode.JumpOp() == asm.Call && ins.Src != asm.PseudoCall
}

// bpfCallBase returns the address of __bpf_call_base, or zero if the symbols
// are unreadable or their addresses hidden.
func bpfCallBase() uint64 {
	callBaseMu.Lock()
	defer callBaseMu.Unlock()
	if callBaseAddr != 0 {
		return callBaseAddr
	}

	f, err := os.Open(kallsymsPath)
	if err != nil {
		return 0
	}
	defer f.Close()

	scanSymbols(f, func(addr uint64, name string) bool {
		if name != "__bpf_call_base" {
			return true
		}
		callBaseAddr = addr
		return false
	})
	return callBaseAddr
}

// scanSymbols calls fn for each symbol in a kallsyms-formatted table until fn
// returns false or the table ends. Symbols at address zero are skipped: that is
// what the kernel shows a reader who is not allowed to see kernel pointers, and
// a name without an address is of no use here.
func scanSymbols(r io.Reader, fn func(addr uint64, name string) bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// "ffffffff81234567 T bpf_get_current_uid_gid", with a fourth
		// bracketed field naming the module for symbols outside vmlinux.
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		if !fn(addr, fields[2]) {
			return
		}
	}
}
