package web

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// TestProgramsMapLinks verifies the programs page renders each referenced map ID
// as a link to that map's details page, and a placeholder when there are none.
func TestProgramsMapLinks(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node: "node-a",
		Tab:  "programs",
		Programs: []*pb.ProgramInfo{
			{Id: 1, Name: "prog_with_maps", MapIds: []uint32{7, 8}, Pids: []*pb.ProcessRef{{Pid: 1234, Comm: "loader"}}},
			{Id: 2, Name: "prog_no_maps"},
		},
		MapsByID: map[uint32]*pb.MapInfo{
			7: {Id: 7, Name: "counters", Type: "Hash"},
			// 8 intentionally absent: link should still render without a tooltip.
		},
	}

	var buf bytes.Buffer
	if err := h.pages["programs"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		`href="/nodes/node-a/maps/7"`,
		`href="/nodes/node-a/maps/8"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q\n%s", want, out)
		}
	}
	// The map-less program must not fabricate a link.
	if strings.Contains(out, `/nodes/node-a/maps/0`) {
		t.Errorf("map-less program should not render a maps/0 link\n%s", out)
	}
	// Map 7 has metadata -> tooltip; map 8 does not -> link but no title.
	if !strings.Contains(out, `title="counters (Hash)"`) {
		t.Errorf("expected tooltip for map 7\n%s", out)
	}
	if strings.Contains(out, `maps/8" title=`) {
		t.Errorf("map 8 has no metadata and should render without a title\n%s", out)
	}
	// Program holder PID + comm is shown.
	if !strings.Contains(out, "loader(1234)") {
		t.Errorf("expected program holder pid/comm loader(1234)\n%s", out)
	}
}

// TestLinksProgLinks verifies the links page renders each link's program as a
// link to that program's page (with a name tooltip), and a placeholder for a
// link that carries no program.
func TestLinksProgLinks(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node: "node-a",
		Tab:  "links",
		Links: []*pb.LinkInfo{
			{Id: 1, Type: "tracing", ProgId: 5},
			{Id: 2, Type: "struct_ops"}, // no prog attached
		},
		Programs: []*pb.ProgramInfo{{Id: 5, Name: "trace_conn"}},
	}

	var buf bytes.Buffer
	if err := h.pages["links"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, `href="/nodes/node-a/programs/5"`) {
		t.Errorf("expected link to program 5\n%s", out)
	}
	if !strings.Contains(out, `title="trace_conn"`) {
		t.Errorf("expected program name tooltip\n%s", out)
	}
	// The prog-less link must not fabricate a programs/0 link.
	if strings.Contains(out, `/nodes/node-a/programs/0`) {
		t.Errorf("prog-less link should not render a programs/0 link\n%s", out)
	}
}

// TestProgramsXlatedDump verifies the program xlated instruction listing renders
// above the programs list when available, and shows the note when it is not.
func TestProgramsXlatedDump(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	base := pageData{
		Node:     "node-a",
		Tab:      "programs",
		Programs: []*pb.ProgramInfo{{Id: 5, Name: "trace_conn"}},
	}

	// Available: listing appears above the "programs on" table.
	avail := base
	avail.ProgDump = &progDumpView{
		ID: 5, Name: "trace_conn", Available: true,
		Lines: []string{"   0: MovImm dst: r0 imm: 0", "   1: Exit"},
	}
	var buf bytes.Buffer
	if err := h.pages["programs"].ExecuteTemplate(&buf, "layout", avail); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "MovImm dst: r0") {
		t.Errorf("expected instruction listing in output\n%s", out)
	}
	dumpPos, listPos := strings.Index(out, "xlated"), strings.Index(out, "programs on node-a")
	if dumpPos < 0 || listPos < 0 || dumpPos > listPos {
		t.Errorf("xlated dump should render above the programs list (dump=%d, list=%d)", dumpPos, listPos)
	}

	// Unavailable: shows the note, not a listing.
	un := base
	un.ProgDump = &progDumpView{ID: 5, Name: "trace_conn", Available: false, Note: "operation not permitted"}
	buf.Reset()
	if err := h.pages["programs"].ExecuteTemplate(&buf, "layout", un); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "unavailable: operation not permitted") {
		t.Errorf("expected unavailable note in output\n%s", out)
	}
}

// TestMapsDumpAboveList verifies the map dump (details) renders above the list
// of maps, so the key/value contents are the first thing seen.
func TestMapsDumpAboveList(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node: "node-a",
		Tab:  "maps",
		Maps: []*pb.MapInfo{{Id: 42, Name: "counters", Dumpable: true}},
		Dump: &dumpView{
			ID:      42,
			Name:    "counters",
			Entries: []*pb.MapEntry{{KeyFmt: "1", KeyHex: "01", ValueFmt: "1000", ValueHex: "e803"}},
		},
	}

	var buf bytes.Buffer
	if err := h.pages["maps"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	dumpPos := strings.Index(out, "contents")
	listPos := strings.Index(out, "maps on node-a")
	if dumpPos < 0 || listPos < 0 {
		t.Fatalf("missing dump (%d) or list (%d) heading\n%s", dumpPos, listPos, out)
	}
	if dumpPos > listPos {
		t.Errorf("dump details should render above the maps list (dump=%d, list=%d)", dumpPos, listPos)
	}
}
