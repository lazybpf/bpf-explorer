package web

import (
	"bytes"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
	"github.com/lazybpf/bpf-explorer/internal/discovery"
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
			pageData{Node: "node-a", GraphHeading: loaderGroupHeading("agent(1000)")},
			"loader: agent(1000) graph - node-a - bpf-explorer",
		},
		{
			"unknown graph", "loader",
			pageData{Node: "node-a", Err: "unknown loader group: sg_9"},
			"graph - node-a - bpf-explorer",
		},
		{
			// Narrowed to a loader, a list page is about that loader: two tabs
			// on the same node's maps are otherwise the same title twice.
			"maps for a loader", "maps",
			pageData{Node: "node-a", MapFilter: &loaderFilter{Group: "sg_1000", Label: "agent(1000)"}},
			"agent(1000) maps - node-a - bpf-explorer",
		},
		{
			"links for a loader", "links",
			pageData{Node: "node-a", LinkFilter: &loaderFilter{Group: "sg_1000", Label: "agent(1000)"}},
			"agent(1000) links - node-a - bpf-explorer",
		},
		{
			"programs for a loader", "programs",
			pageData{Node: "node-a", ProgFilter: &loaderFilter{Group: "sg_1000", Label: "agent(1000)"}},
			"agent(1000) programs - node-a - bpf-explorer",
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

// TestTabClass covers the three states of a tab bar entry. "active" claims you
// are on that page, so a sub-page must not use it: it would be a lie, and it
// made the old "all maps" back link look like a duplicate of a highlighted tab.
func TestTabClass(t *testing.T) {
	tests := []struct {
		tab  string
		sub  bool
		name string
		want string
	}{
		{"maps", false, "maps", "active"},
		{"maps", true, "maps", "parent"},
		{"maps", false, "programs", ""},
		{"maps", true, "programs", ""},
		{"loaders", true, "loaders", "parent"},
	}
	for _, tc := range tests {
		if got := tabClass(tc.tab, tc.sub, tc.name); got != tc.want {
			t.Errorf("tabClass(%q, %v, %q) = %q, want %q", tc.tab, tc.sub, tc.name, got, tc.want)
		}
	}
}

// TestRenderMarksSubPages verifies render decides the tab state from the page
// name, so a dump reached by any route gets the parent marking and a list does
// not, without either template knowing about it.
func TestRenderMarksSubPages(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	h.render(rec, "mapdump", pageData{Node: "node-a", Tab: "maps", Dump: &dumpView{ID: 42}})
	if out := rec.Body.String(); !strings.Contains(out, `<a class="parent" href="/nodes/node-a/maps">`) {
		t.Errorf("map dump should mark the maps tab as parent\n%s", out)
	}

	rec = httptest.NewRecorder()
	h.render(rec, "maps", pageData{Node: "node-a", Tab: "maps"})
	if out := rec.Body.String(); !strings.Contains(out, `<a class="active" href="/nodes/node-a/maps">`) {
		t.Errorf("maps list should mark the maps tab as active\n%s", out)
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

// TestProgramsLoaderFilterRender checks the narrowed programs page says whose
// programs it is showing and offers the ways back out - the filter arrives from
// another page, so the tab bar alone cannot undo it.
func TestProgramsLoaderFilterRender(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node: "node-a",
		Tab:  "programs",
		Programs: []*pb.ProgramInfo{{
			Id: 5, Name: "trace_conn", Type: "Tracing",
			Pids: []*pb.ProcessRef{{Pid: 1000, Comm: "agent"}, {Pid: 4242, Comm: "holder"}},
		}},
		ProgFilter:  &loaderFilter{Group: "sg_1000", Label: "agent(1000)", Total: 9},
		ProgLoaders: []loaderChoice{{Group: "sg_1000", Label: "agent(1000)", Count: 1}},
	}

	var buf bytes.Buffer
	if err := h.pages["programs"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	// How many of how many, in the heading's count: on its own it would look
	// like the whole node.
	if !strings.Contains(out, "(1 of 9)") {
		t.Errorf("expected the filtered count against the node total\n%s", out)
	}
	// Named once by the heading and once by the picker's option, as on the
	// other two filtered pages - the row's own Holders cell names it a third
	// time, which is the column doing its job rather than the filter repeating
	// itself.
	if n := strings.Count(out, "agent(1000)"); n != 3 {
		t.Errorf("loader named %d times, want the heading, the picker's option and the row\n%s", n, out)
	}
	if strings.Contains(out, "loader: agent(1000)") {
		t.Errorf("the picker's own label already says \"loader\"\n%s", out)
	}
	// Unlike the links page's Loader column, Holders stays: only the
	// lowest-numbered holder names the group, so the column is not one value
	// repeated down the rows.
	if !strings.Contains(out, ">Holders</th>") || !strings.Contains(out, "holder(4242)") {
		t.Errorf("filtered programs page dropped the holders column\n%s", out)
	}
	if cols := strings.Count(out, "</th>"); cols != 7 {
		t.Errorf("filtered table has %d columns, want the unfiltered 7\n%s", cols, out)
	}
	// The way back to everything is the picker's first option.
	if !strings.Contains(out, `<option value=""`) {
		t.Errorf("expected an all-loaders option to undo the filter\n%s", out)
	}
	if !strings.Contains(out, `href="/nodes/node-a/loaders/sg_1000"`) {
		t.Errorf("expected a link to this group's graph\n%s", out)
	}
	// Still the programs tab, not a sub-page of it: the page is the list,
	// narrowed.
	if !strings.Contains(out, `class="active" href="/nodes/node-a/programs"`) {
		t.Errorf("programs tab should stay active\n%s", out)
	}
}

// TestProgramsLoaderPicker checks the programs page can narrow itself: the
// picker is there with no filter applied, marks the selected group when one is,
// and is absent when the node has nothing to narrow.
func TestProgramsLoaderPicker(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	choices := []loaderChoice{
		{Group: "sg_1000", Label: "agent(1000)", Count: 4},
		{Group: unattachedGroupID, Label: unattachedLabel, Count: 2},
	}

	render := func(data pageData) string {
		t.Helper()
		var buf bytes.Buffer
		if err := h.pages["programs"].ExecuteTemplate(&buf, "layout", data); err != nil {
			t.Fatalf("execute: %v", err)
		}
		return buf.String()
	}

	// Arrived at the page directly: the picker offers every group that loaded
	// something, with its count, and nothing is selected but "all loaders".
	out := render(pageData{Node: "node-a", Tab: "programs", ProgLoaders: choices})
	for _, want := range []string{
		`action="/nodes/node-a/programs"`,
		`<select name="loader"`,
		`<option value="" selected>all loaders</option>`,
		`<option value="sg_1000">agent(1000) (4)</option>`,
		`<option value="sg_unattached">` + unattachedLabel + ` (2)</option>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("picker missing %q\n%s", want, out)
		}
	}

	// With a filter on, that group is the selected option.
	out = render(pageData{
		Node: "node-a", Tab: "programs", ProgLoaders: choices,
		ProgFilter: &loaderFilter{Group: "sg_1000", Label: "agent(1000)", Total: 6},
	})
	if !strings.Contains(out, `<option value="sg_1000" selected>`) {
		t.Errorf("picker does not mark the active group\n%s", out)
	}
	if strings.Contains(out, `<option value="" selected>`) {
		t.Errorf("all-loaders should not be selected under a filter\n%s", out)
	}

	// Nothing to narrow: no picker at all.
	if out := render(pageData{Node: "node-a", Tab: "programs"}); strings.Contains(out, `<select name="loader"`) {
		t.Errorf("picker rendered with no loaders to choose\n%s", out)
	}
}

// TestLinksLoaderFilterRender checks the narrowed links page says whose links
// it is showing and offers the ways back out - the filter arrives from another
// page, so the tab bar alone cannot undo it.
func TestLinksLoaderFilterRender(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node:        "node-a",
		Tab:         "links",
		Links:       []*pb.LinkInfo{{Id: 1, Type: "tracing", ProgId: 5}},
		Programs:    []*pb.ProgramInfo{{Id: 5, Name: "trace_conn"}},
		LinkFilter:  &loaderFilter{Group: "sg_1000", Label: "agent(1000)", Total: 9},
		LinkLoaders: []loaderChoice{{Group: "sg_1000", Label: "agent(1000)", Count: 1}},
	}

	var buf bytes.Buffer
	if err := h.pages["links"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "agent(1000)") {
		t.Errorf("filtered page does not name the loader\n%s", out)
	}
	// How many of how many, in the heading's count: on its own it would look
	// like the whole node.
	if !strings.Contains(out, "(1 of 9)") {
		t.Errorf("expected the filtered count against the node total\n%s", out)
	}
	// The loader is named once. It was said three times - heading, picker and a
	// note under them - before this was compacted.
	if n := strings.Count(out, "agent(1000)"); n != 2 {
		t.Errorf("loader named %d times, want twice: the heading and the picker's option\n%s", n, out)
	}
	if strings.Contains(out, "loader: agent(1000)") {
		t.Errorf("the picker's own label already says \"loader\"\n%s", out)
	}
	// And the loader column goes with it: under a filter every row carries the
	// same value. The unfiltered table still has it - TestLinksColumnsExplained.
	if strings.Contains(out, ">Loader</th>") {
		t.Errorf("loader column is constant under a filter and should be dropped\n%s", out)
	}
	if cols := strings.Count(out, "</th>"); cols != 5 {
		t.Errorf("filtered table has %d columns, want 5\n%s", cols, out)
	}
	// The way back to everything is the picker's first option.
	if !strings.Contains(out, `<option value=""`) {
		t.Errorf("expected an all-loaders option to undo the filter\n%s", out)
	}
	if !strings.Contains(out, `href="/nodes/node-a/loaders/sg_1000"`) {
		t.Errorf("expected a link to this group's graph\n%s", out)
	}
	// Still the links tab, not a sub-page of it: the page is the list, narrowed.
	if !strings.Contains(out, `class="active" href="/nodes/node-a/links"`) {
		t.Errorf("links tab should stay active\n%s", out)
	}
}

// TestMapsLoaderFilterRender checks the narrowed maps page says whose maps it is
// showing and offers the ways back out - the filter arrives from another page,
// so the tab bar alone cannot undo it.
func TestMapsLoaderFilterRender(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node:       "node-a",
		Tab:        "maps",
		Maps:       []*pb.MapInfo{{Id: 12, Name: "m_a", Type: "Hash", Pids: []*pb.ProcessRef{{Pid: 4242, Comm: "holder"}}}},
		MapFilter:  &loaderFilter{Group: "sg_1000", Label: "agent(1000)", Total: 9},
		MapLoaders: []loaderChoice{{Group: "sg_1000", Label: "agent(1000)", Count: 1}},
	}

	var buf bytes.Buffer
	if err := h.pages["maps"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	// How many of how many, in the heading's count: on its own it would look
	// like the whole node.
	if !strings.Contains(out, "(1 of 9)") {
		t.Errorf("expected the filtered count against the node total\n%s", out)
	}
	// Named once by the heading and once by the picker's option, as on the
	// links page.
	if n := strings.Count(out, "agent(1000)"); n != 2 {
		t.Errorf("loader named %d times, want twice: the heading and the picker's option\n%s", n, out)
	}
	if strings.Contains(out, "loader: agent(1000)") {
		t.Errorf("the picker's own label already says \"loader\"\n%s", out)
	}
	// Unlike the links page's Loader column, Holders stays: a map is grouped by
	// the programs referencing it, not by who holds an fd, so the column is not
	// the group's name repeated down the rows.
	if !strings.Contains(out, ">Holders</th>") || !strings.Contains(out, "holder(4242)") {
		t.Errorf("filtered maps page dropped the holders column\n%s", out)
	}
	if cols := strings.Count(out, "</th>"); cols != 9 {
		t.Errorf("filtered table has %d columns, want the unfiltered 9\n%s", cols, out)
	}
	// The way back to everything is the picker's first option.
	if !strings.Contains(out, `<option value=""`) {
		t.Errorf("expected an all-loaders option to undo the filter\n%s", out)
	}
	if !strings.Contains(out, `href="/nodes/node-a/loaders/sg_1000"`) {
		t.Errorf("expected a link to this group's graph\n%s", out)
	}
	// Still the maps tab, not a sub-page of it: the page is the list, narrowed.
	if !strings.Contains(out, `class="active" href="/nodes/node-a/maps"`) {
		t.Errorf("maps tab should stay active\n%s", out)
	}
}

// TestMapsLoaderPicker checks the maps page can narrow itself: the picker is
// there with no filter applied, marks the selected group when one is, and is
// absent when the node has no maps to narrow.
func TestMapsLoaderPicker(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	choices := []loaderChoice{
		{Group: "sg_1000", Label: "agent(1000)", Count: 4},
		{Group: unattachedGroupID, Label: unattachedLabel, Count: 2},
	}

	render := func(data pageData) string {
		t.Helper()
		var buf bytes.Buffer
		if err := h.pages["maps"].ExecuteTemplate(&buf, "layout", data); err != nil {
			t.Fatalf("execute: %v", err)
		}
		return buf.String()
	}

	// Arrived at the page directly: the picker offers every group with maps,
	// with their counts, and nothing is selected but "all loaders".
	out := render(pageData{Node: "node-a", Tab: "maps", MapLoaders: choices})
	for _, want := range []string{
		`action="/nodes/node-a/maps"`,
		`<select name="loader"`,
		`<option value="" selected>all loaders</option>`,
		`<option value="sg_1000">agent(1000) (4)</option>`,
		`<option value="sg_unattached">` + unattachedLabel + ` (2)</option>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("picker missing %q\n%s", want, out)
		}
	}
	// A map two loaders share is listed under each, so the counts here can add
	// up to more than the node has maps - the picker has to say so.
	if !strings.Contains(out, "more maps than the node has") {
		t.Errorf("picker does not explain the overlapping counts\n%s", out)
	}

	// With a filter on, that group is the selected option.
	out = render(pageData{
		Node: "node-a", Tab: "maps", MapLoaders: choices,
		MapFilter: &loaderFilter{Group: "sg_1000", Label: "agent(1000)", Total: 6},
	})
	if !strings.Contains(out, `<option value="sg_1000" selected>`) {
		t.Errorf("picker does not mark the active group\n%s", out)
	}
	if strings.Contains(out, `<option value="" selected>`) {
		t.Errorf("all-loaders should not be selected under a filter\n%s", out)
	}

	// Nothing to narrow: no picker at all.
	if out := render(pageData{Node: "node-a", Tab: "maps"}); strings.Contains(out, `<select name="loader"`) {
		t.Errorf("picker rendered with no loaders to choose\n%s", out)
	}
}

// TestLinksUnfilteredHasNoFilterNote guards the plain page against the note
// leaking into it.
func TestLinksUnfilteredHasNoFilterNote(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{Node: "node-a", Tab: "links", Links: []*pb.LinkInfo{{Id: 1}}}
	var buf bytes.Buffer
	if err := h.pages["links"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out := buf.String(); strings.Contains(out, "grouped as the loaders page counts them") {
		t.Errorf("unfiltered page shows the filter note\n%s", out)
	}
}

// TestLinksColumnsExplained pins the links table's headers: the program column
// is spelled out like every other header in the app rather than abbreviated the
// way bpftool prints it, and the columns whose content needs explaining carry
// it, since this table is the only place a link's attach detail appears.
func TestLinksColumnsExplained(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var buf bytes.Buffer
	data := pageData{Node: "node-a", Tab: "links", Links: []*pb.LinkInfo{{Id: 1, ProgId: 5}}}
	if err := h.pages["links"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "<th>Prog</th>") {
		t.Errorf("program column should not be abbreviated\n%s", out)
	}
	if !strings.Contains(out, ">Program</th>") {
		t.Errorf("expected a Program column\n%s", out)
	}
	// Every header on this table is documented; th[title] is what marks it.
	for _, col := range []string{">ID</th>", ">Type</th>", ">Program</th>", ">Loader</th>", ">Attach</th>"} {
		i := strings.Index(out, col)
		if i < 0 {
			t.Errorf("missing column %s\n%s", col, out)
			continue
		}
		if head := out[strings.LastIndex(out[:i], "<th"):i]; !strings.Contains(head, "title=") {
			t.Errorf("column %s carries no explanation", col)
		}
	}
}

// TestListPagesExplainIDs keeps the id explanation from being something only
// the links page says: the same recycling caveat applies to every kernel id.
func TestListPagesExplainIDs(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, page := range []string{"maps", "programs", "links"} {
		var buf bytes.Buffer
		if err := h.pages[page].ExecuteTemplate(&buf, "layout", pageData{Node: "node-a", Tab: page}); err != nil {
			t.Fatalf("execute %s: %v", page, err)
		}
		if !strings.Contains(buf.String(), "recycles ids") {
			t.Errorf("%s page does not explain what an id is", page)
		}
	}
}

// TestLinksLoaderPicker checks the links page can narrow itself: the picker is
// there with no filter applied, marks the selected group when one is, and is
// absent when the node has no links to narrow.
func TestLinksLoaderPicker(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	choices := []loaderChoice{
		{Group: "sg_1000", Label: "agent(1000)", Count: 4},
		{Group: unattachedGroupID, Label: unattachedLabel, Count: 2},
	}

	render := func(data pageData) string {
		t.Helper()
		var buf bytes.Buffer
		if err := h.pages["links"].ExecuteTemplate(&buf, "layout", data); err != nil {
			t.Fatalf("execute: %v", err)
		}
		return buf.String()
	}

	// Arrived at the page directly: the picker offers every group with links,
	// with their counts, and nothing is selected but "all loaders".
	out := render(pageData{Node: "node-a", Tab: "links", LinkLoaders: choices})
	for _, want := range []string{
		`action="/nodes/node-a/links"`,
		`<select name="loader"`,
		`<option value="" selected>all loaders</option>`,
		`<option value="sg_1000">agent(1000) (4)</option>`,
		`<option value="sg_unattached">` + unattachedLabel + ` (2)</option>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("picker missing %q\n%s", want, out)
		}
	}

	// With a filter on, that group is the selected option.
	out = render(pageData{
		Node: "node-a", Tab: "links", LinkLoaders: choices,
		LinkFilter: &loaderFilter{Group: "sg_1000", Label: "agent(1000)", Total: 6},
	})
	if !strings.Contains(out, `<option value="sg_1000" selected>`) {
		t.Errorf("picker does not mark the active group\n%s", out)
	}
	if strings.Contains(out, `<option value="" selected>`) {
		t.Errorf("all-loaders should not be selected under a filter\n%s", out)
	}

	// Nothing to narrow: no picker at all.
	if out := render(pageData{Node: "node-a", Tab: "links"}); strings.Contains(out, `<select name="loader"`) {
		t.Errorf("picker rendered with no loaders to choose\n%s", out)
	}
}

// TestLoaderPickersSubmitOnChange covers the one gesture the picker takes:
// choosing a group is the request, so the form carries the marker the layout's
// script wires a change listener to. The submit button stays in the markup - the
// script only hides it - so the filter still works with JS off.
func TestLoaderPickersSubmitOnChange(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	choices := []loaderChoice{{Group: "sg_1000", Label: "agent(1000)", Count: 4}}

	for _, tc := range []struct {
		page string
		data pageData
	}{
		{"programs", pageData{Node: "node-a", Tab: "programs", ProgLoaders: choices}},
		{"maps", pageData{Node: "node-a", Tab: "maps", MapLoaders: choices}},
		{"links", pageData{Node: "node-a", Tab: "links", LinkLoaders: choices}},
	} {
		var buf bytes.Buffer
		if err := h.pages[tc.page].ExecuteTemplate(&buf, "layout", tc.data); err != nil {
			t.Fatalf("execute %s: %v", tc.page, err)
		}
		out := buf.String()
		for _, want := range []string{
			`data-autosubmit`,
			`<button type="submit">filter</button>`,
			`form[data-autosubmit]`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s page missing %q\n%s", tc.page, want, out)
			}
		}
	}
}

// TestLinksBadLoaderGroupRejected covers a hand-edited URL: the group is read
// before anything is fetched for the page, so a malformed one is a 400 rather
// than a silently unfiltered list of every link on the node.
func TestLinksBadLoaderGroupRejected(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	router := h.Router()

	for _, group := range []string{"1000", "sg_nope", "sg_"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/nodes/node-a/links?loader="+group, nil)
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET ?loader=%s = %d, want %d", group, rec.Code, http.StatusBadRequest)
		}
	}
}

// TestMapsBadLoaderGroupRejected covers a hand-edited URL, as on the links page:
// the group is read before anything is fetched, so a malformed one is a 400
// rather than a silently unfiltered list of every map on the node.
func TestMapsBadLoaderGroupRejected(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	router := h.Router()

	for _, group := range []string{"1000", "sg_nope", "sg_"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/nodes/node-a/maps?loader="+group, nil)
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET ?loader=%s = %d, want %d", group, rec.Code, http.StatusBadRequest)
		}
	}

	// A dump is one map, so the filter means nothing there and is not read: a
	// stray group must not turn a map's contents into a 400. Reaching that far
	// needs a discoverer; the node is not one it knows, so the page renders the
	// "unknown node" error without dialling anything.
	disc, derr := discovery.ParseStatic("other=127.0.0.1:1")
	if derr != nil {
		t.Fatalf("ParseStatic: %v", derr)
	}
	dh, err := New(disc, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nodes/node-a/maps/12?loader=sg_nope", nil)
	dh.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("dump page with a stray loader group = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestProgramsBadLoaderGroupRejected covers a hand-edited URL, as on the other
// two list pages: the group is read before anything is fetched, so a malformed
// one is a 400 rather than a silently unfiltered list of every program on the
// node.
func TestProgramsBadLoaderGroupRejected(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	router := h.Router()

	for _, group := range []string{"1000", "sg_nope", "sg_"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/nodes/node-a/programs?loader="+group, nil)
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET ?loader=%s = %d, want %d", group, rec.Code, http.StatusBadRequest)
		}
	}

	// An xlated listing is one program, so the filter means nothing there and
	// is not read: a stray group must not turn it into a 400. Reaching that far
	// needs a discoverer; the node is not one it knows, so the page renders the
	// "unknown node" error without dialling anything.
	disc, derr := discovery.ParseStatic("other=127.0.0.1:1")
	if derr != nil {
		t.Fatalf("ParseStatic: %v", derr)
	}
	dh, err := New(disc, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nodes/node-a/programs/5?loader=sg_nope", nil)
	dh.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("xlated page with a stray loader group = %d, want %d", rec.Code, http.StatusOK)
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

	// Sub is what render sets for a dump page; the tab bar reads it.
	base := pageData{
		Node:     "node-a",
		Tab:      "programs",
		Sub:      true,
		Programs: []*pb.ProgramInfo{{Id: 5, Name: "trace_conn"}},
	}

	lines := []string{
		"int trace_conn(struct __sk_buff * skb):",
		"; if (skb->len > limit)",
		"   0: (79) r1 = *(u64 *)(r8 +24)",
		"   1: (2d) if r1 > r2 goto pc+4",
		"   2: (15) if r1 == 0xfffffff5 goto pc+3",
		"   3: (85) call bpf_map_lookup_elem#149280",
		"   4: (18) r1 = map[id:422]",
		"; ",
		"   6: (95) exit",
	}
	avail := base
	avail.ProgDump = &progDumpView{
		ID: 5, Name: "trace_conn", Available: true,
		Lines: xlatedLines(lines, "node-a", map[uint32]*pb.MapInfo{
			422: {Id: 422, Name: "conns", Type: "hash"},
		}),
	}
	var buf bytes.Buffer
	if err := h.pages["progdump"].ExecuteTemplate(&buf, "layout", avail); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	// Marked up or not, the listing has to still read as the text the agent
	// sent, since diffing it against bpftool is the point of the page. This
	// also catches a stray newline in the template, which inside a pre would
	// show up as a blank line between every pair of instructions.
	if got := listingText(t, out); got != strings.Join(lines, "\n") {
		t.Errorf("listing text changed:\n got %q\nwant %q", got, strings.Join(lines, "\n"))
	}
	// The helper a call lands in, and the map a load names - the two things
	// worth picking out of the wall of instructions.
	if !strings.Contains(out, `<span class="helper">bpf_map_lookup_elem</span>`) {
		t.Errorf("expected the helper name marked in output\n%s", out)
	}
	if !strings.Contains(out, `href="/nodes/node-a/maps/422"`) {
		t.Errorf("expected the map reference linked in output\n%s", out)
	}
	if !strings.Contains(out, `title="conns (hash) (new tab)"`) {
		t.Errorf("expected the map link to name the map in output\n%s", out)
	}
	// A hex value keeps the text bpftool printed and hangs its decimal off a
	// tooltip, so the listing still diffs but the number can be read.
	if !strings.Contains(out, `<span class="hex" title="4294967285₁₀ (signed -11)">0xfffffff5</span>`) {
		t.Errorf("expected the hex comparand to carry its decimal in output\n%s", out)
	}
	// A register says what it is for on hover, which is the one thing the
	// listing never spells out anywhere.
	if !strings.Contains(out, `<span class="reg" title="argument 1, and the context pointer when the program starts">r1</span>`) {
		t.Errorf("expected a register to carry its role in output\n%s", out)
	}
	// And the convention behind all of them is on the page too, folded away
	// until it is asked for.
	if !strings.Contains(out, `<table id="regs" class="kv regs" hidden>`) {
		t.Errorf("expected the register cheat sheet, hidden, in output\n%s", out)
	}
	if !strings.Contains(out, `<th scope="row">r6–r9</th>`) {
		t.Errorf("expected the callee-saved registers on the cheat sheet\n%s", out)
	}
	// Both views can be put aside, the convention can be opened, and the listing
	// can be taken away as text; the buttons say what they will do.
	for _, want := range []string{
		`id="comments"`, `id="instructions"`, `id="registers"`, `id="copy"`,
		">hide comments<", ">hide instructions<", ">show registers<", ">copy listing<",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s among the listing controls\n%s", want, out)
		}
	}
	// Disassembly is full of characters that would otherwise read as markup, so
	// it has to arrive escaped.
	if strings.Contains(out, "if r1 > r2") {
		t.Errorf("jump condition reached the page as raw markup\n%s", out)
	}
	if strings.Contains(out, `programs on <span class="name">node-a</span>`) {
		t.Errorf("xlated page should not repeat the programs list\n%s", out)
	}
	// The way back up is the tab bar, marked as the section this page sits under.
	if !strings.Contains(out, `<a class="parent" href="/nodes/node-a/programs">`) {
		t.Errorf("xlated page needs the programs tab marked as its parent\n%s", out)
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
		Sub:  true, // what render sets for a dump page
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
	if strings.Contains(out, `maps on <span class="name">node-a</span>`) {
		t.Errorf("dump page should not repeat the maps list\n%s", out)
	}
	// The way back up is the tab bar, marked as the section this page sits under.
	if !strings.Contains(out, `<a class="parent" href="/nodes/node-a/maps">`) {
		t.Errorf("dump page needs the maps tab marked as its parent\n%s", out)
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

// tagPattern strips our own markup - not a general HTML parser, just enough to
// read a rendered listing back as text.
var tagPattern = regexp.MustCompile(`<[^>]*>`)

// listingText recovers what a reader sees from a marked-up dump: the line divs
// become the newlines they render as, the spans and links go, and the entities
// come back.
func listingText(t *testing.T, page string) string {
	t.Helper()

	const open = `<pre id="out" class="xlated">`
	start := strings.Index(page, open)
	if start < 0 {
		t.Fatalf("no listing in page:\n%s", page)
	}
	inner := page[start+len(open):]
	end := strings.Index(inner, "</pre>")
	if end < 0 {
		t.Fatalf("unterminated listing in page:\n%s", page)
	}

	text := strings.ReplaceAll(inner[:end], "</div>", "\n")
	text = tagPattern.ReplaceAllString(text, "")
	return html.UnescapeString(strings.TrimSuffix(text, "\n"))
}

// fakeDisc answers with a fixed set of endpoints, in the order it was given
// them: the Kubernetes discoverer returns pods in API order, so node names do
// not arrive sorted, and a discoverer can fail outright.
type fakeDisc struct {
	eps []discovery.Endpoint
	err error
}

func (f fakeDisc) Endpoints() ([]discovery.Endpoint, error) { return f.eps, f.err }

// TestIndexOpensTheFirstNode: the index has nothing to show that the next page
// does not carry in its header, so it opens a node instead of asking for one -
// the first by name, whatever order the discoverer listed them in.
func TestIndexOpensTheFirstNode(t *testing.T) {
	disc := fakeDisc{eps: []discovery.Endpoint{
		{Node: "node-c", Addr: "127.0.0.1:3"},
		{Node: "node-a", Addr: "127.0.0.1:1"},
		{Node: "node-b", Addr: "127.0.0.1:2"},
	}}
	h, err := New(disc, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	h.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusFound {
		t.Errorf("GET / = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != "/nodes/node-a/loaders" {
		t.Errorf("GET / opened %q, want %q", got, "/nodes/node-a/loaders")
	}

	// The same sort orders the picker, which would otherwise reshuffle between
	// page loads.
	rec = httptest.NewRecorder()
	h.render(rec, "maps", pageData{Node: "node-a", Tab: "maps", Nodes: mustNodes(t, h)})
	out := rec.Body.String()
	if i, j := strings.Index(out, ">node-a<"), strings.Index(out, ">node-c<"); i > j {
		t.Errorf("expected the picker in name order\n%s", out)
	}
}

// TestIndexWithNoAgents: with nothing to open the index is the page that says
// so, and says what to check.
func TestIndexWithNoAgents(t *testing.T) {
	h, err := New(fakeDisc{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("GET / = %d, want %d", rec.Code, http.StatusOK)
	}
	out := rec.Body.String()
	for _, want := range []string{"no agents discovered", "found no agent pods", "--agents=node=host:port"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the empty index to say %q\n%s", want, out)
		}
	}
}

// TestIndexDiscoveryError: nothing found and nothing asked are different
// answers. A discoverer that failed cannot say the cluster has no agents, so
// the page reports the failure instead of advice about the DaemonSet.
func TestIndexDiscoveryError(t *testing.T) {
	h, err := New(fakeDisc{err: errors.New("list pods: forbidden")}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	out := rec.Body.String()
	if !strings.Contains(out, "list pods: forbidden") {
		t.Errorf("expected the discovery error on the page\n%s", out)
	}
	if strings.Contains(out, "found no agent pods") {
		t.Errorf("a failed lookup is not an empty cluster\n%s", out)
	}
}

// TestTabBarLeadsWithTheLandingTab keeps the bar and the index in step: a node
// opens on defaultTab, so that is the tab the bar starts with. An active tab
// in the middle of the row reads as one you clicked into from the left of it.
func TestTabBarLeadsWithTheLandingTab(t *testing.T) {
	h, err := New(fakeDisc{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.render(rec, "maps", pageData{Node: "node-a", Tab: "maps"})

	out := rec.Body.String()
	bar := out[strings.Index(out, `<p class="tabs">`):]
	first := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(bar)
	if first == nil {
		t.Fatalf("no tabs in the bar\n%s", out)
	}
	if want := "/nodes/node-a/" + defaultTab; first[1] != want {
		t.Errorf("the bar starts with %q, want %q - the tab a node opens on\n%s", first[1], want, out)
	}
}

func mustNodes(t *testing.T, h *Handlers) []string {
	t.Helper()
	names, err := h.nodes()
	if err != nil {
		t.Fatalf("nodes: %v", err)
	}
	return names
}

// TestInnerMapLoadersInheritsOuterHolder covers the case Daniel hit with
// tetragon: an ArrayOfMaps holds a Hash in a slot, and the loader closed the
// inner map's fd after inserting it. Nothing holds the inner map, nothing pins
// it and no program names it in map_ids, so only the outer map's slot is left
// to credit it by - which is also why `bpftool map show` prints no pids for it.
func TestInnerMapLoadersInheritsOuterHolder(t *testing.T) {
	progs := []*pb.ProgramInfo{
		{Id: 1769, Name: "filter_arg", MapIds: []uint32{18733}},
	}
	maps := []*pb.MapInfo{
		{Id: 18733, Name: "string_maps_0", Type: "ArrayOfMaps",
			Pids:        []*pb.ProcessRef{{Pid: 107547, Comm: "tetragon"}},
			InnerMapIds: []uint32{18798}},
		{Id: 18798, Name: "string_maps_0_0", Type: "Hash"},
	}

	want := "tetragon(107547) via map 18733"
	if got := innerMapLoaders(progs, maps, 18798); len(got) != 1 || got[0] != want {
		t.Errorf("innerMapLoaders(18798) = %v, want [%q]", got, want)
	}
	// The outer map is credited by its own holder, not by this route.
	if got := innerMapLoaders(progs, maps, 18733); len(got) != 0 {
		t.Errorf("innerMapLoaders(18733) = %v, want none", got)
	}
}

// TestInnerMapLoadersOuterHeldByProgram checks the inner map still inherits
// when the outer map has no fd holder either and is only reachable through a
// program referencing it - the inner row must never name a loader the outer
// row does not.
func TestInnerMapLoadersOuterHeldByProgram(t *testing.T) {
	progs := []*pb.ProgramInfo{
		{Id: 27, Name: "prog", MapIds: []uint32{10},
			Pids: []*pb.ProcessRef{{Pid: 1234, Comm: "loader"}}},
	}
	maps := []*pb.MapInfo{
		{Id: 10, Name: "outer", Type: "ArrayOfMaps", InnerMapIds: []uint32{11}},
		{Id: 11, Name: "inner", Type: "Hash"},
	}
	want := "loader(1234) via map 10"
	if got := innerMapLoaders(progs, maps, 11); len(got) != 1 || got[0] != want {
		t.Errorf("innerMapLoaders(11) = %v, want [%q]", got, want)
	}

	// With no loader anywhere up the chain there is nothing to inherit.
	progs[0].Pids = nil
	if got := innerMapLoaders(progs, maps, 11); len(got) != 0 {
		t.Errorf("innerMapLoaders(11) = %v, want none when the outer map has no loader", got)
	}
}

// TestInnerMapLoadersGroupsOuterMaps checks one loader holding the same inner
// map through two outer maps is named once, with both outer ids.
func TestInnerMapLoadersGroupsOuterMaps(t *testing.T) {
	maps := []*pb.MapInfo{
		{Id: 10, Name: "outer_a", Type: "ArrayOfMaps", InnerMapIds: []uint32{12},
			Pids: []*pb.ProcessRef{{Pid: 1234, Comm: "loader"}}},
		{Id: 11, Name: "outer_b", Type: "ArrayOfMaps", InnerMapIds: []uint32{12},
			Pids: []*pb.ProcessRef{{Pid: 1234, Comm: "loader"}}},
		{Id: 12, Name: "inner", Type: "Hash"},
	}
	want := "loader(1234) via map 10, 11"
	if got := innerMapLoaders(nil, maps, 12); len(got) != 1 || got[0] != want {
		t.Errorf("innerMapLoaders(12) = %v, want [%q]", got, want)
	}
}

// TestMapsInnerMapLoaderRendered checks the Holders column falls all the way
// through to the outer map for an inner map of a map-of-maps, and that the
// three routes keep their precedence: own holder, then referencing program,
// then outer map.
func TestMapsInnerMapLoaderRendered(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := pageData{
		Node: "node-a",
		Tab:  "maps",
		Maps: []*pb.MapInfo{
			{Id: 18733, Name: "string_maps_0", Type: "ArrayOfMaps",
				Pids:        []*pb.ProcessRef{{Pid: 107547, Comm: "tetragon"}},
				InnerMapIds: []uint32{18798}},
			{Id: 18798, Name: "string_maps_0_0", Type: "Hash"}, // inner -> inherits
			{Id: 99, Name: "orphan", Type: "Hash"},             // nothing points at it
		},
		Programs: []*pb.ProgramInfo{
			{Id: 1769, Name: "filter_arg", MapIds: []uint32{18733}},
		},
	}

	var buf bytes.Buffer
	if err := h.pages["maps"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "tetragon(107547) via map 18733") {
		t.Errorf("inner map should inherit the outer map's loader\n%s", out)
	}
	// The outer map keeps its own holder, unqualified: its row names tetragon
	// without inheriting anything, since it holds the fd itself.
	outerRow := rowFor(t, out, "string_maps_0<")
	if !strings.Contains(outerRow, "tetragon(107547)") || strings.Contains(outerRow, "via") {
		t.Errorf("outer map row should show its own holder directly, got %q", outerRow)
	}
	// A map nothing reaches still reads as a placeholder, which is the
	// no-loader group's membership rule.
	if !strings.Contains(out, `<span class="muted">-</span>`) {
		t.Errorf("orphan map should still render a placeholder\n%s", out)
	}
}

// rowFor returns the rendered table row containing marker, so an assertion can
// be made about one map's cells rather than the whole page.
func rowFor(t *testing.T, page, marker string) string {
	t.Helper()
	for _, row := range strings.Split(page, "<tr>") {
		if strings.Contains(row, marker) {
			return row
		}
	}
	t.Fatalf("no row containing %q", marker)
	return ""
}
