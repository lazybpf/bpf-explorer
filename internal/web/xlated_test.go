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

func TestXlatedParts(t *testing.T) {
	maps := map[uint32]*pb.MapInfo{422: {Id: 422, Name: "exec_args", Type: "hash"}}

	tests := []struct {
		name string
		text string
		want []xlatedPart
	}{
		{
			"a plain instruction is one run",
			"r8 = r1",
			[]xlatedPart{{Text: "r8 = r1"}},
		},
		{
			"a helper call marks the name, not the offset it carries",
			"call bpf_get_current_uid_gid#242800",
			[]xlatedPart{
				{Text: "call "},
				{Text: "bpf_get_current_uid_gid", Helper: true},
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
				{Text: "r1 = "},
				{Text: "map[id:422]", Href: "/nodes/node-a/maps/422", Title: "exec_args (hash)"},
				{Text: ""},
			},
		},
		{
			// The offset into the value is not part of the map's name.
			"a direct value load links only the map",
			"r1 = map[id:422][0]+8",
			[]xlatedPart{
				{Text: "r1 = "},
				{Text: "map[id:422]", Href: "/nodes/node-a/maps/422", Title: "exec_args (hash)"},
				{Text: "[0]+8"},
			},
		},
		{
			"a map the node did not list still links",
			"r1 = map[id:999]",
			[]xlatedPart{
				{Text: "r1 = "},
				{Text: "map[id:999]", Href: "/nodes/node-a/maps/999"},
				{Text: ""},
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
	if len(parts) < 2 || parts[1].Href != "/nodes/node%2F..%2Fa%20b/maps/1" {
		t.Errorf("xlatedParts() href = %q, want the node path-escaped", parts[1].Href)
	}
}
