package web

import (
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// The input lines here are the ones internal/inspector/disasm.go writes, since
// what this parses is that formatter's output.
func TestXlatedLines(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		kind   string
		text   string
		offset string
		opcode string
	}{
		{"a function header with its signature", "int ig_execve_e(struct syscall_trace_enter * ctx):", xlatedFunc, "int ig_execve_e(struct syscall_trace_enter * ctx):", "", ""},
		{"a function header without BTF", "trace_conn:", xlatedFunc, "trace_conn:", "", ""},
		{"a source line", "; uid_t uid = (u32)bpf_get_current_uid_gid();", xlatedComment, "uid_t uid = (u32)bpf_get_current_uid_gid();", "", ""},
		{
			// bpftool prints the marker even when the line info is blank, so
			// this is a line of the listing, not nothing.
			"a blank source line", "; ", xlatedComment, "", "", "",
		},
		{"an instruction", "   0: (bf) r8 = r1", xlatedInsn, "", "   0", "bf"},
		{"a wide offset", "1024: (95) exit", xlatedInsn, "", "1024", "95"},
		{
			// An opcode neither we nor bpftool decodes still numbers its line.
			"an undecodable instruction", "   5: BUG_ldx_81", xlatedInsn, "", "   5", "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := xlatedLines([]string{tt.line}, "node-a", nil)
			if len(got) != 1 {
				t.Fatalf("xlatedLines(%q) returned %d lines, want 1", tt.line, len(got))
			}
			line := got[0]
			if line.Kind != tt.kind {
				t.Errorf("Kind = %q, want %q", line.Kind, tt.kind)
			}
			if line.Text != tt.text {
				t.Errorf("Text = %q, want %q", line.Text, tt.text)
			}
			if line.Offset != tt.offset {
				t.Errorf("Offset = %q, want %q", line.Offset, tt.offset)
			}
			if line.Opcode != tt.opcode {
				t.Errorf("Opcode = %q, want %q", line.Opcode, tt.opcode)
			}
		})
	}
}

// reg is what a register part looks like: the roles themselves are checked by
// TestRegTitle, so naming them here would only restate the table twice.
func reg(name string) xlatedPart {
	return xlatedPart{Text: name, Class: classReg, Title: regTitle(name)}
}

func TestXlatedParts(t *testing.T) {
	maps := map[uint32]*pb.MapInfo{422: {Id: 422, Name: "exec_args", Type: "hash"}}

	tests := []struct {
		name string
		text string
		want []xlatedPart
	}{
		{
			"every register is marked, and what is between them is one run",
			"r8 = r1",
			[]xlatedPart{reg("r8"), {Text: " = "}, reg("r1")},
		},
		{
			// The 32-bit view of a register is still that register.
			"a 32-bit operand is marked too",
			"w2 += w3",
			[]xlatedPart{reg("w2"), {Text: " += "}, reg("w3")},
		},
		{
			"a helper call marks the name, not the offset it carries",
			"call bpf_get_current_uid_gid#242800",
			[]xlatedPart{
				{Text: "call "},
				{Text: "bpf_get_current_uid_gid", Class: classHelper},
				{Text: "#242800"},
			},
		},
		{
			// "unknown" is the placeholder for a call that could not be named:
			// marking it would dress it up as a symbol.
			"an unnamed call marks nothing",
			"call unknown#242800",
			[]xlatedPart{{Text: "call unknown#242800"}},
		},
		{
			"a call to another BPF function has no name to mark",
			"call pc+6",
			[]xlatedPart{{Text: "call pc+6"}},
		},
		{
			"a map reference links to the map, and says which it is",
			"r1 = map[id:422]",
			[]xlatedPart{
				reg("r1"),
				{Text: " = "},
				{Text: "map[id:422]", Href: "/nodes/node-a/maps/422", Title: "exec_args (hash)"},
			},
		},
		{
			// The offset into the value is not part of the map's name.
			"a direct value load links only the map",
			"r1 = map[id:422][0]+8",
			[]xlatedPart{
				reg("r1"),
				{Text: " = "},
				{Text: "map[id:422]", Href: "/nodes/node-a/maps/422", Title: "exec_args (hash)"},
				{Text: "[0]+8"},
			},
		},
		{
			"a map the node did not list still links",
			"r1 = map[id:999]",
			[]xlatedPart{
				reg("r1"),
				{Text: " = "},
				{Text: "map[id:999]", Href: "/nodes/node-a/maps/999"},
			},
		},
		{
			"a jump comparand carries its decimal",
			"if r1 == 0xff goto pc+3",
			[]xlatedPart{
				{Text: "if "},
				reg("r1"),
				{Text: " == "},
				{Text: "0xff", Class: classHex, Title: "255₁₀"},
				{Text: " goto pc+3"},
			},
		},
		{
			// The kernel prints the comparand unsigned however the comparison
			// reads it, so an errno check arrives here as a large number.
			"a comparand with the top bit set also reads as signed",
			"if r0 s> 0xfffffff5 goto pc+2",
			[]xlatedPart{
				{Text: "if "},
				reg("r0"),
				{Text: " s> "},
				{Text: "0xfffffff5", Class: classHex, Title: "4294967285₁₀ (signed -11)"},
				{Text: " goto pc+2"},
			},
		},
		{
			"a wide immediate reads as a 64-bit value",
			"r1 = 0xffffffffffffffff",
			[]xlatedPart{
				reg("r1"),
				{Text: " = "},
				{Text: "0xffffffffffffffff", Class: classHex, Title: "18446744073709551615₁₀ (signed -1)"},
			},
		},
		{
			// Past 32 bits but with room to spare: nothing to read as signed.
			"a wide immediate with no top bit set is just decimal",
			"r1 = 0x100000000",
			[]xlatedPart{
				reg("r1"),
				{Text: " = "},
				{Text: "0x100000000", Class: classHex, Title: "4294967296₁₀"},
			},
		},
		{
			// The ALU immediates already print decimal, so there is nothing here
			// to restate.
			"a decimal immediate is left alone",
			"r2 += 255",
			[]xlatedPart{reg("r2"), {Text: " += 255"}},
		},
		{
			// A load off the frame pointer, which is where every stack slot in
			// a listing is addressed from.
			"a stack load marks both registers",
			"r1 = *(u64 *)(r10 -8)",
			[]xlatedPart{
				reg("r1"),
				{Text: " = *(u64 *)("},
				reg("r10"),
				{Text: " -8)"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := xlatedParts(tt.text, "node-a", maps)
			if len(got) != len(tt.want) {
				t.Fatalf("xlatedParts(%q) = %+v, want %+v", tt.text, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("part %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// A node name reaches the page as part of a URL, so it has to be escaped there
// rather than trusted to be a bare hostname.
func TestXlatedPartsEscapesNode(t *testing.T) {
	parts := xlatedParts("r1 = map[id:1]", "node/../a b", nil)
	if len(parts) < 3 || parts[2].Href != "/nodes/node%2F..%2Fa%20b/maps/1" {
		t.Errorf("xlatedParts() href = %q, want the node path-escaped", parts[2].Href)
	}
}

// The tooltip is the whole of what the page says about a register in place, so
// what it says is the feature: which slot of the calling convention this is,
// and for a wN that it is only the low half of it.
func TestRegTitle(t *testing.T) {
	tests := []struct {
		tok  string
		want string
	}{
		{"r0", "the return value: a helper call's result, and the program's exit code"},
		{"r1", "argument 1, and the context pointer when the program starts"},
		{"r5", "argument 5, destroyed by a call"},
		{"r6", "callee-saved: it keeps its value across a call"},
		{"r10", "the frame pointer: the top of this frame's stack, and read-only"},
		{"w1", "the low 32 bits of r1 - argument 1, and the context pointer when the program starts"},
		{"w10", "the low 32 bits of r10 - the frame pointer: the top of this frame's stack, and read-only"},
	}

	for _, tt := range tests {
		if got := regTitle(tt.tok); got != tt.want {
			t.Errorf("regTitle(%q) = %q, want %q", tt.tok, got, tt.want)
		}
	}
}
