package web

import (
	"fmt"
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
)

// Line kinds. A dump is a listing of instructions with the function headers and
// source lines its BTF carries interleaved, and the page lets the reader put
// either of those aside.
const (
	xlatedFunc    = "func"
	xlatedComment = "comment"
	xlatedInsn    = "insn"
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

// xlatedPart is a run of an instruction's text: plain, the name of a helper, or
// a reference to a map, which links to that map's own dump.
type xlatedPart struct {
	Text   string
	Helper bool
	Href   string // non-empty: link Text there
	Title  string // a link's tooltip: what the map is
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
// does; a load of a map pointer names the map, and nothing else does.
func xlatedParts(text, node string, maps map[uint32]*pb.MapInfo) []xlatedPart {
	// A call the dump could not name has no name to mark - "unknown" is a
	// placeholder, not a symbol.
	if m := callPattern.FindStringSubmatch(text); m != nil && m[1] != "unknown" {
		return []xlatedPart{
			{Text: "call "},
			{Text: m[1], Helper: true},
			// From the "#" on: the id or offset the call carries.
			{Text: text[len(m[0])-1:]},
		}
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
			return []xlatedPart{{Text: text[:m[0]]}, ref, {Text: text[m[1]:]}}
		}
	}

	return []xlatedPart{{Text: text}}
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
