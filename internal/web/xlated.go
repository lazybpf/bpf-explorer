package web

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// A program dump arrives as the lines `bpftool prog dump xlated` would print,
// because that text is the point: it is what someone diffs against bpftool. So
// the page reads the meaning back out of it here rather than the agent sending
// it twice. Both sides are ours - internal/inspector/disasm.go writes these
// lines - and the patterns below are the grammar it writes them in.
var (
	// "   0: (bf) r8 = r1". The opcode is optional because an instruction
	// neither we nor bpftool can decode prints as "   5: BUG_ldx_81", and that
	// is still a numbered line rather than a heading.
	insnPattern = regexp.MustCompile(`^(\s*\d+): (?:\(([0-9a-f]{2})\) )?(.*)$`)
	// "call bpf_get_current_uid_gid#242800", the name being what to mark.
	callPattern = regexp.MustCompile(`^call ([A-Za-z_][A-Za-z0-9_]*)#`)
	// "map[id:422]", which is also the head of "map[id:422][0]+8".
	mapPattern = regexp.MustCompile(`map\[id:(\d+)\]`)
	// What is worth a tooltip inside a run of instruction text, in one pass
	// because the two never overlap - there is no letter r or w in a hex digit.
	//
	// A hex literal is a jump's comparand or the value of a wide immediate
	// load. A register is "r1", or "w1" where the operation works on the low 32
	// bits; r10 is spelled before the single digits, or the alternation would
	// match "r1" and leave a stray "0" behind. The word boundaries keep both out
	// of a name that happens to contain one, since a call's target is whatever
	// kallsyms called it - and an underscore is a word character, so a helper
	// named like bpf_r1_read is safe too.
	tokenPattern = regexp.MustCompile(`\b0x[0-9a-fA-F]+\b|\b[rw](?:10|[0-9])\b`)
)

// Line kinds. A dump is a listing of instructions with the function headers and
// source lines its BTF carries interleaved, and the page lets the reader put
// either of those aside.
const (
	xlatedFunc    = "func"
	xlatedComment = "comment"
	xlatedInsn    = "insn"
)

// Part classes, which are the CSS classes the listing marks a run with.
const (
	classHelper = "helper"
	classHex    = "hex"
	classReg    = "reg"
)

// xlatedLine is one line of a program dump, split into what the page marks up.
type xlatedLine struct {
	Kind string
	// Text is the function header, or a comment's source line without its
	// marker. Empty for an instruction, and for a comment whose source line
	// was blank - which bpftool still prints, so it is a line, not nothing.
	Text   string
	Offset string // an instruction's position, as printed: right-aligned
	Opcode string // its raw opcode byte, in hex
	Parts  []xlatedPart
}

// xlatedPart is a run of an instruction's text: plain, the name of a helper, a
// hex value, a register, or a reference to a map, which links to that map's own
// dump.
type xlatedPart struct {
	Text  string
	Class string // non-empty: wrap Text in a span of this class
	Href  string // non-empty: link Text there
	// Tooltip: what the map is, what the hex value is in decimal, or what the
	// register is for.
	Title string
}

// xlatedLines parses a dump into the page's model. maps may be nil, in which
// case a map reference still links, just without a tooltip naming it.
func xlatedLines(lines []string, node string, maps map[uint32]*pb.MapInfo) []xlatedLine {
	out := make([]xlatedLine, 0, len(lines))
	for _, line := range lines {
		if comment, ok := strings.CutPrefix(line, "; "); ok {
			out = append(out, xlatedLine{Kind: xlatedComment, Text: comment})
			continue
		}
		m := insnPattern.FindStringSubmatch(line)
		if m == nil {
			// Whatever is neither an instruction nor a source line is the
			// header a function starts with.
			out = append(out, xlatedLine{Kind: xlatedFunc, Text: line})
			continue
		}
		out = append(out, xlatedLine{
			Kind:   xlatedInsn,
			Offset: m[1],
			Opcode: m[2],
			Parts:  xlatedParts(m[3], node, maps),
		})
	}
	return out
}

// xlatedParts splits one instruction's text at the name worth marking. There is
// at most one per instruction: a call names what it lands in, and nothing else
// does; a load of a map pointer names the map, and nothing else does. Whatever
// is left over is still split at its hex values by plainParts.
func xlatedParts(text, node string, maps map[uint32]*pb.MapInfo) []xlatedPart {
	// A call the dump could not name has no name to mark - "unknown" is a
	// placeholder, not a symbol.
	if m := callPattern.FindStringSubmatch(text); m != nil && m[1] != "unknown" {
		parts := []xlatedPart{
			{Text: "call "},
			{Text: m[1], Class: classHelper},
		}
		// From the "#" on: the id or offset the call carries.
		return append(parts, plainParts(text[len(m[0])-1:])...)
	}

	// A map reference is the one thing in a listing that points at another
	// object on the node, so it is the one thing worth a link.
	if m := mapPattern.FindStringSubmatchIndex(text); m != nil {
		if id, err := strconv.ParseUint(text[m[2]:m[3]], 10, 32); err == nil {
			ref := xlatedPart{
				Text: text[m[0]:m[1]],
				Href: fmt.Sprintf("/nodes/%s/maps/%d", url.PathEscape(node), id),
			}
			if info := maps[uint32(id)]; info != nil {
				ref.Title = fmt.Sprintf("%s (%s)", info.GetName(), info.GetType())
			}
			parts := append(plainParts(text[:m[0]]), ref)
			return append(parts, plainParts(text[m[1]:])...)
		}
	}

	return plainParts(text)
}

// plainParts splits a run of instruction text at the values that can say more
// about themselves than they print.
//
// A hex value carries what it is in decimal: the listing prints hex because
// bpftool does, but what a comparand means is a number - an errno, a size, a
// flag - and reading it back out of the hex is otherwise the reader's job. A
// register carries what it is for, which is nowhere in the listing at all: rN
// is a name for a slot in a calling convention the reader is expected to have
// memorised.
func plainParts(text string) []xlatedPart {
	matches := tokenPattern.FindAllStringIndex(text, -1)
	if matches == nil {
		return plainRun(text)
	}

	parts := make([]xlatedPart, 0, 2*len(matches)+1)
	end := 0
	for _, m := range matches {
		tok := text[m[0]:m[1]]
		part := xlatedPart{Text: tok, Class: classReg, Title: regTitle(tok)}
		if strings.HasPrefix(tok, "0x") {
			dec, ok := hexDecimal(tok)
			if !ok {
				// Wider than 64 bits, so nothing we can restate. Leaving it in
				// the run that follows prints it unchanged.
				continue
			}
			part.Class, part.Title = classHex, dec
		}
		parts = append(parts, plainRun(text[end:m[0]])...)
		parts = append(parts, part)
		end = m[1]
	}
	return append(parts, plainRun(text[end:])...)
}

// plainRun is a run with nothing to mark in it, and nothing at all when it is
// empty: most instructions begin or end on a register, and a part that renders
// as no characters is not a run of the listing.
func plainRun(text string) []xlatedPart {
	if text == "" {
		return nil
	}
	return []xlatedPart{{Text: text}}
}

// regRoles is what each register is for, by number. Terse deliberately: this is
// read at a glance with the eye still on the instruction, and the cheat sheet
// the page can open is where the fuller version lives.
var regRoles = [11]string{
	"the return value: a helper call's result, and the program's exit code",
	"argument 1, and the context pointer when the program starts",
	"argument 2, destroyed by a call",
	"argument 3, destroyed by a call",
	"argument 4, destroyed by a call",
	"argument 5, destroyed by a call",
	"callee-saved: it keeps its value across a call",
	"callee-saved: it keeps its value across a call",
	"callee-saved: it keeps its value across a call",
	"callee-saved: it keeps its value across a call",
	"the frame pointer: the top of this frame's stack, and read-only",
}

// regTitle is the tooltip for a register: what it is for, and for a wN that it
// is the low half of the register of the same number. tokenPattern matched to
// get here, so the number is one of the eleven.
func regTitle(tok string) string {
	n, _ := strconv.Atoi(tok[1:])
	if tok[0] == 'w' {
		return fmt.Sprintf("the low 32 bits of r%d - %s", n, regRoles[n])
	}
	return regRoles[n]
}

// registerRow is one row of the register cheat sheet the dump page can open.
type registerRow struct {
	Regs string
	Role string
}

// registerSheet says what the tooltips say, at the grain of the convention
// rather than of one register: eleven rows, one per register, would bury the
// three groups that are the thing to learn.
//
// Short sentences, plain verbs, no idiom: this is the row a reader falls back
// on when the terse tooltip did not land, and half of them are reading it in a
// second language.
func registerSheet() []registerRow {
	return []registerRow{
		{"r0", "the return value. A helper call stores its result here, and the program returns its exit code here."},
		{"r1–r5", "the arguments to a call, in order. Every call destroys all five values, so a value that is needed after the call must be copied to r6–r9 first. When the program starts, r1 holds the context pointer, and the function header above gives its type."},
		{"r6–r9", "safe across a call: these four keep their values, so the compiler uses them for values it needs later."},
		{"r10", "the frame pointer, which no instruction can write to. It marks the top of this frame's 512-byte stack, and local variables are below it: \"r10 -8\" is the first 8 bytes of them."},
		{"w0–w10", "the low 32 bits of the register with the same number. The listing prints wN when the operation is 32-bit. Such an operation sets the upper 32 bits to zero."},
	}
}

// base10 is the subscript the tooltip carries, marking that what it shows is
// the same value in another base rather than a different value. A tooltip is a
// title attribute, which is text: the subscript has to be the characters, since
// there is no markup to be had there.
const base10 = "₁₀" // subscript one, subscript zero

// hexDecimal restates a hex value in decimal. One whose top bit is set at its
// width gets its signed reading too, because that is usually what it is: the
// kernel prints a jump's comparand unsigned whatever the signedness of the
// comparison, so a check against -EAGAIN arrives here as 0xfffffff5.
func hexDecimal(lit string) (string, bool) {
	v, err := strconv.ParseUint(lit[len("0x"):], 16, 64)
	if err != nil {
		return "", false
	}
	switch {
	case v > math.MaxInt64:
		return fmt.Sprintf("%d%s (signed %d)", v, base10, int64(v)), true
	case v > math.MaxInt32 && v <= math.MaxUint32:
		return fmt.Sprintf("%d%s (signed %d)", v, base10, int32(uint32(v))), true
	}
	return strconv.FormatUint(v, 10) + base10, true
}

// mapsByID indexes a map listing for the pages that resolve a map id to what it
// is: the programs list's tooltips, and a dump's map references.
func mapsByID(maps []*pb.MapInfo) map[uint32]*pb.MapInfo {
	byID := make(map[uint32]*pb.MapInfo, len(maps))
	for _, m := range maps {
		byID[m.GetId()] = m
	}
	return byID
}
