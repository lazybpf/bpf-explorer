package web

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// TestPageTitle covers the browser tab titles: with a tab per object, each has
// to name its object before the node and the app, since truncation eats the end.
func TestPageTitle(t *testing.T) {
	tests := []struct {
		name string
		page string
		data pageData
		want string
	}{
		{"index", "index", pageData{}, "bpf-explorer"},
		{"maps list", "maps", pageData{Node: "node-a"}, "maps - node-a - bpf-explorer"},
		{"tracelog", "tracelog", pageData{Node: "node-a"}, "tracelog - node-a - bpf-explorer"},
		{
			"map dump", "mapdump",
			pageData{Node: "node-a", Dump: &dumpView{ID: 42, Name: "counters"}},
			"map 42: counters dump - node-a - bpf-explorer",
		},
		{
			"nameless map dump", "mapdump",
			pageData{Node: "node-a", Dump: &dumpView{ID: 42}},
			"map 42 dump - node-a - bpf-explorer",
		},
		{
			// DumpMap failed, so there is no dumpView to name.
			"failed map dump", "mapdump",
			pageData{Node: "node-a", Err: "boom"},
			"map dump - node-a - bpf-explorer",
		},
		{
			"prog xlated", "progdump",
			pageData{Node: "node-a", ProgDump: &progDumpView{ID: 5, Name: "trace_conn"}},
			"prog 5: trace_conn xlated - node-a - bpf-explorer",
		},
		{
			"loader graph", "loader",
			pageData{Node: "node-a", GraphLabel: "loader: agent(1000)"},
			"loader: agent(1000) graph - node-a - bpf-explorer",
		},
		{
			"unknown graph", "loader",
			pageData{Node: "node-a", Err: "unknown loader group: sg_9"},
			"graph - node-a - bpf-explorer",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pageTitle(tc.page, tc.data); got != tc.want {
				t.Errorf("pageTitle(%q) = %q, want %q", tc.page, got, tc.want)
			}
		})
	}
}

// TestRenderSetsTitle verifies render injects the title, so no handler has to
// remember to - a page added later gets a real tab name for free.
func TestRenderSetsTitle(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	h.render(rec, "mapdump", pageData{
		Node: "node-a",
		Dump: &dumpView{ID: 42, Name: "counters"},
	})
	if want := `<title>map 42: counters dump - node-a - bpf-explorer</title>`; !strings.Contains(rec.Body.String(), want) {
		t.Errorf("expected %s\n%s", want, rec.Body.String())
	}
}

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

// TestProgramsXlatedDump verifies the xlated listing gets a page of its own -
// no programs list repeated underneath, a link back to it instead - and that it
// shows the agent's note when the listing is unavailable.
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

	avail := base
	avail.ProgDump = &progDumpView{
		ID: 5, Name: "trace_conn", Available: true,
		Lines: []string{"   0: MovImm dst: r0 imm: 0", "   1: Exit"},
	}
	var buf bytes.Buffer
	if err := h.pages["progdump"].ExecuteTemplate(&buf, "layout", avail); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "MovImm dst: r0") {
		t.Errorf("expected instruction listing in output\n%s", out)
	}
	if strings.Contains(out, "programs on node-a") {
		t.Errorf("xlated page should not repeat the programs list\n%s", out)
	}
	if !strings.Contains(out, `href="/nodes/node-a/programs"`) {
		t.Errorf("xlated page needs a link back to the programs list\n%s", out)
	}

	// Unavailable: shows the note, not a listing.
	un := base
	un.ProgDump = &progDumpView{ID: 5, Name: "trace_conn", Available: false, Note: "operation not permitted"}
	buf.Reset()
	if err := h.pages["progdump"].ExecuteTemplate(&buf, "layout", un); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "unavailable: operation not permitted") {
		t.Errorf("expected unavailable note in output\n%s", out)
	}
}

// TestMapsDumpOwnPage verifies a map's contents get a page of their own, with a
// link back to the list rather than a second copy of it.
func TestMapsDumpOwnPage(t *testing.T) {
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
	if err := h.pages["mapdump"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "contents") || !strings.Contains(out, "e803") {
		t.Errorf("expected the map's contents\n%s", out)
	}
	// The list stays in the tab this dump was opened from; repeating it is noise.
	if strings.Contains(out, "maps on node-a") {
		t.Errorf("dump page should not repeat the maps list\n%s", out)
	}
	if !strings.Contains(out, `href="/nodes/node-a/maps"`) {
		t.Errorf("dump page needs a link back to the maps list\n%s", out)
	}
	// data.Maps is still populated (it names the dumped map) but must not render
	// as a table of its own.
	if strings.Contains(out, ">graph</a>") {
		t.Errorf("dump page should carry no per-row actions\n%s", out)
	}
}

// TestMapsUndumpableShowsReason verifies an undumpable map still renders a
// "dump" control, inert and carrying the agent's reason as a tooltip, rather
// than the bare "n/a" it used to show. A dumpable map keeps a real link.
func TestMapsUndumpableShowsReason(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node: "node-a",
		Tab:  "maps",
		Maps: []*pb.MapInfo{
			{Id: 42, Name: "counters", Type: "Hash", Dumpable: true},
			{Id: 43, Name: "events", Type: "RingBuf", DumpNote: "event stream, not a keyed map"},
			{Id: 44, Name: "mystery", Type: "Future"}, // undumpable, agent sent no note
		},
	}

	var buf bytes.Buffer
	if err := h.pages["maps"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, `href="/nodes/node-a/maps/42"`) {
		t.Errorf("dumpable map should keep a real dump link\n%s", out)
	}
	// The reason the agent gave reaches the tooltip.
	if !strings.Contains(out, `title="cannot dump this map: event stream, not a keyed map"`) {
		t.Errorf("expected the agent's dump note as a tooltip\n%s", out)
	}
	// A note-less undumpable map still explains itself rather than going bare.
	if !strings.Contains(out, `title="cannot dump this map: this map type does not support key iteration"`) {
		t.Errorf("expected fallback tooltip when the agent sent no note\n%s", out)
	}
	// The undumpable maps must not be clickable.
	for _, id := range []string{"43", "44"} {
		if strings.Contains(out, `href="/nodes/node-a/maps/`+id+`"`) {
			t.Errorf("undumpable map %s should not render a dump link\n%s", id, out)
		}
	}
	if strings.Contains(out, ">n/a<") {
		t.Errorf("the bare n/a placeholder should be gone\n%s", out)
	}
}

// TestMapsGraphLink verifies every map row offers a graph link - unlike dump,
// which the map type can rule out - and that it opens in its own tab.
func TestMapsGraphLink(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node: "node-a",
		Tab:  "maps",
		Maps: []*pb.MapInfo{
			{Id: 42, Name: "counters", Type: "Hash", Dumpable: true},
			{Id: 43, Name: "events", Type: "RingBuf"}, // undumpable, still graphable
		},
	}

	var buf bytes.Buffer
	if err := h.pages["maps"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	for _, id := range []string{"42", "43"} {
		if !strings.Contains(out, `href="/nodes/node-a/loaders/map/`+id+`" target="_blank"`) {
			t.Errorf("map %s missing a graph link opening in a new tab\n%s", id, out)
		}
	}
	if n := strings.Count(out, ">graph</a>"); n != 2 {
		t.Errorf("want a graph link per map row, got %d\n%s", n, out)
	}
}

// TestMapsDumpHexTooltip verifies a dump's hex cells carry an ASCII tooltip when
// the bytes hold readable text, and none when they don't.
func TestMapsDumpHexTooltip(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node: "node-a",
		Tab:  "maps",
		Maps: []*pb.MapInfo{{Id: 42, Name: "comms", Dumpable: true}},
		Dump: &dumpView{
			ID:   42,
			Name: "comms",
			Entries: []*pb.MapEntry{
				// key: u32 1 (no printable byte), value: "bash" NUL-padded.
				{KeyFmt: "1", KeyHex: "01000000", ValueFmt: "...", ValueHex: "6261736800000000"},
			},
		},
	}

	var buf bytes.Buffer
	if err := h.pages["mapdump"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, `<code title="ASCII: bash....">6261736800000000</code>`) {
		t.Errorf("expected ASCII tooltip on the value hex cell\n%s", out)
	}
	if !strings.Contains(out, `<code>01000000</code>`) {
		t.Errorf("counter key should render without a tooltip\n%s", out)
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
