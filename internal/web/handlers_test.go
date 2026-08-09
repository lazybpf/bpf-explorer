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

// TestMapsPIDs verifies the maps list renders each map's holder processes, and a
// placeholder for a map nobody holds an fd to (pinned only, or no hostPID).
func TestMapsPIDs(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node: "node-a",
		Tab:  "maps",
		Maps: []*pb.MapInfo{
			{Id: 42, Name: "counters", Pids: []*pb.ProcessRef{
				{Pid: 1234, Comm: "loader"}, {Pid: 5678, Comm: "agent"},
			}},
			{Id: 43, Name: "orphan"},
		},
	}

	var buf bytes.Buffer
	if err := h.pages["maps"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"loader(1234)", "agent(5678)"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected map holder %q\n%s", want, out)
		}
	}
	if !strings.Contains(out, `<span class="muted">-</span>`) {
		t.Errorf("map without holders should render a placeholder\n%s", out)
	}
}

// TestMapsDerivedLoader verifies that a map nothing holds an fd to (.rodata and
// friends, whose fd the loader closes once the program is loaded) falls back to
// the loader of a program referencing it, and that a map with its own holders
// does not.
func TestMapsDerivedLoader(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	loader := []*pb.ProcessRef{{Pid: 1234, Comm: "loader"}}
	data := pageData{
		Node: "node-a",
		Tab:  "maps",
		Maps: []*pb.MapInfo{
			{Id: 7, Name: ".rodata"}, // no holder -> derived
			{Id: 8, Name: "counters", Pids: []*pb.ProcessRef{{Pid: 5678, Comm: "agent"}}}, // own holder -> direct
			{Id: 9, Name: "orphan"}, // referenced by nobody
		},
		Programs: []*pb.ProgramInfo{
			{Id: 27, Name: "prog_a", MapIds: []uint32{7, 8}, Pids: loader},
			{Id: 31, Name: "prog_b", MapIds: []uint32{7}, Pids: loader}, // same loader -> one entry, both progs
		},
	}

	var buf bytes.Buffer
	if err := h.pages["maps"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "loader(1234) via prog 27, 31") {
		t.Errorf("expected derived loader for the holder-less map\n%s", out)
	}
	// The map with its own holder shows that, not the program's loader.
	if !strings.Contains(out, "agent(5678)") {
		t.Errorf("expected direct holder for map 8\n%s", out)
	}
	if strings.Contains(out, "loader(1234) via prog 27</span>") {
		t.Errorf("map 8 has a holder and must not fall back to a derived loader\n%s", out)
	}
	if !strings.Contains(out, `<span class="muted">-</span>`) {
		t.Errorf("map referenced by no program should still render a placeholder\n%s", out)
	}
}

// TestMapLoadersSkipsHolderlessProgram verifies a map is not credited to a
// program that has no holder of its own (pinned or link-held).
func TestMapLoadersSkipsHolderlessProgram(t *testing.T) {
	progs := []*pb.ProgramInfo{
		{Id: 27, Name: "pinned_prog", MapIds: []uint32{7}},
		{Id: 31, Name: "other", MapIds: []uint32{8}, Pids: []*pb.ProcessRef{{Pid: 1234, Comm: "loader"}}},
	}
	if got := mapLoaders(progs, 7); len(got) != 0 {
		t.Errorf("mapLoaders(7) = %v, want none", got)
	}
	want := "loader(1234) via prog 31"
	if got := mapLoaders(progs, 8); len(got) != 1 || got[0] != want {
		t.Errorf("mapLoaders(8) = %v, want [%q]", got, want)
	}
}
