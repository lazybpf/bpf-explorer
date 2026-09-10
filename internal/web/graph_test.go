package web

import (
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

func sampleGraphData() ([]*pb.ProgramInfo, []*pb.MapInfo, []*pb.LinkInfo) {
	progs := []*pb.ProgramInfo{
		{Id: 7, Name: "p_a", Type: "XDP", MapIds: []uint32{12}, Pids: []*pb.ProcessRef{{Pid: 1000, Comm: "agent"}}},
		{Id: 8, Name: "p_b", Type: "Kprobe", MapIds: []uint32{13}, Pids: []*pb.ProcessRef{{Pid: 2000, Comm: "profiler"}}},
		{Id: 9, Name: "p_c", Type: "TC"}, // no loader
	}
	maps := []*pb.MapInfo{
		{Id: 12, Name: "m_a", Type: "Hash"},
		{Id: 13, Name: "m_b", Type: "Array"},
		{Id: 99, Name: "orphan", Type: "Hash"}, // referenced by nobody
	}
	links := []*pb.LinkInfo{{Id: 3, Type: "xdp", ProgId: 7}}
	return progs, maps, links
}

func findGroup(groups []*loaderGroupData, id string) *loaderGroupData {
	for _, g := range groups {
		if g.ID == id {
			return g
		}
	}
	return nil
}

func TestGroupByLoader(t *testing.T) {
	progs, maps, links := sampleGraphData()
	groups, _ := groupByLoader(progs, maps, links, nil)

	agent := findGroup(groups, "sg_1000")
	if agent == nil || agent.Label != "loader: agent(1000)" {
		t.Fatalf("missing/mislabelled agent group: %+v", agent)
	}
	if len(agent.Progs) != 1 || agent.Progs[0].GetId() != 7 {
		t.Errorf("agent group progs = %+v, want just prog 7", agent.Progs)
	}
	if len(agent.Maps) != 1 || agent.Maps[0] != 12 {
		t.Errorf("agent group maps = %v, want [12]", agent.Maps)
	}
	if len(agent.Links) != 1 || agent.Links[0].GetId() != 3 {
		t.Errorf("agent group links = %+v, want link 3", agent.Links)
	}

	un := findGroup(groups, unattachedGroupID)
	if un == nil {
		t.Fatal("missing no-loader group")
	}
	if len(un.Progs) != 1 || un.Progs[0].GetId() != 9 {
		t.Errorf("no-loader progs = %+v, want prog 9", un.Progs)
	}
	// Orphan map 99 must land in the no-loader group.
	found := false
	for _, mid := range un.Maps {
		if mid == 99 {
			found = true
		}
	}
	if !found {
		t.Errorf("no-loader maps = %v, want to include 99", un.Maps)
	}
}

func TestGroupByLoaderHidesPID(t *testing.T) {
	// A program held by both systemd(1) and agent(1000) should group under agent
	// when PID 1 is hidden.
	progs := []*pb.ProgramInfo{
		{Id: 7, Name: "p", Type: "XDP", Pids: []*pb.ProcessRef{{Pid: 1, Comm: "systemd"}, {Pid: 1000, Comm: "agent"}}},
	}
	groups, _ := groupByLoader(progs, nil, nil, map[uint32]bool{1: true})
	if findGroup(groups, "sg_1") != nil {
		t.Errorf("systemd (PID 1) group should be hidden")
	}
	if g := findGroup(groups, "sg_1000"); g == nil {
		t.Errorf("program should group under agent(1000) when PID 1 hidden; groups=%+v", groups)
	}
}

func TestBuildGroupMermaid(t *testing.T) {
	progs, maps, links := sampleGraphData()
	groups, mapByID := groupByLoader(progs, maps, links, nil)
	out := string(buildGroupMermaid(findGroup(groups, "sg_1000"), mapByID, "node-a"))

	for _, want := range []string{
		"graph LR",
		`prog_7["prog 7: p_a (XDP)"]`,
		`map_12[("map 12: m_a (Hash)")]`,
		`link_3{{"link 3: xdp"}}`,
		"link_3 -->|attaches| prog_7",
		"prog_7 -->|uses| map_12",
		`click prog_7 "/nodes/node-a/loaders/prog/7"`,
		`click map_12 "/nodes/node-a/maps/12"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("group mermaid missing %q\n%s", want, out)
		}
	}
	// The agent group must not contain the other loader's program.
	if strings.Contains(out, "prog_8") {
		t.Errorf("agent group leaked prog_8\n%s", out)
	}
}

func TestProgramGroupData(t *testing.T) {
	prog := &pb.ProgramInfo{Id: 7, Name: "p_a", Type: "XDP", MapIds: []uint32{12, 12, 13}}
	links := []*pb.LinkInfo{
		{Id: 3, Type: "xdp", ProgId: 7},
		{Id: 4, Type: "tracing", ProgId: 8}, // different program -> excluded
	}
	g := programGroupData(prog, links)

	if len(g.Progs) != 1 || g.Progs[0].GetId() != 7 {
		t.Errorf("want just prog 7, got %+v", g.Progs)
	}
	if len(g.Maps) != 2 || g.Maps[0] != 12 || g.Maps[1] != 13 {
		t.Errorf("want deduped maps [12 13], got %v", g.Maps)
	}
	if len(g.Links) != 1 || g.Links[0].GetId() != 3 {
		t.Errorf("want only link 3 (attaches prog 7), got %+v", g.Links)
	}
}

func TestMapGroupData(t *testing.T) {
	progs := []*pb.ProgramInfo{
		{Id: 8, Name: "p_b", MapIds: []uint32{12, 13}},
		{Id: 7, Name: "p_a", MapIds: []uint32{12}},
		{Id: 9, Name: "p_c", MapIds: []uint32{13}}, // does not reference 12
	}
	links := []*pb.LinkInfo{
		{Id: 4, Type: "xdp", ProgId: 7},
		{Id: 3, Type: "tracing", ProgId: 9}, // attaches a program outside the group
		{Id: 5, Type: "struct_ops"},         // no program at all
	}
	g := mapGroupData(12, progs, links)

	if len(g.Maps) != 1 || g.Maps[0] != 12 {
		t.Errorf("want just map 12, got %v", g.Maps)
	}
	// Referencing programs only, ordered by id.
	if len(g.Progs) != 2 || g.Progs[0].GetId() != 7 || g.Progs[1].GetId() != 8 {
		t.Errorf("want progs [7 8], got %+v", g.Progs)
	}
	if len(g.Links) != 1 || g.Links[0].GetId() != 4 {
		t.Errorf("want only link 4 (attaches prog 7), got %+v", g.Links)
	}
}

// TestBuildGroupMermaidFocusedMap covers the map-focused diagram: a program in
// it references maps outside the group, which must not leak in as bare nodes.
func TestBuildGroupMermaidFocusedMap(t *testing.T) {
	progs := []*pb.ProgramInfo{{Id: 8, Name: "p_b", Type: "Kprobe", MapIds: []uint32{12, 12, 13}}}
	mapByID := map[uint32]*pb.MapInfo{
		12: {Id: 12, Name: "m_a", Type: "Hash"},
		13: {Id: 13, Name: "m_b", Type: "Array"},
	}
	out := string(buildGroupMermaid(mapGroupData(12, progs, nil), mapByID, "node-a"))

	for _, want := range []string{
		`map_12[("map 12: m_a (Hash)")]`,
		"prog_8 -->|uses| map_12",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("map diagram missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "map_13") {
		t.Errorf("map 13 is outside the focused group and must not appear\n%s", out)
	}
	// MapIds lists 12 twice; the arrow must still be drawn once.
	if n := strings.Count(out, "prog_8 -->|uses| map_12"); n != 1 {
		t.Errorf("want 1 edge to map 12, got %d\n%s", n, out)
	}
}

func TestLoadersIndexRender(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data := pageData{
		Node: "node-a", Tab: "loaders",
		Loaders: []loaderSummary{{ID: "sg_1000", Label: "loader: agent(1000)", Progs: 2, Maps: 3, Links: 1}},
	}
	var buf strings.Builder
	if err := h.pages["loaders"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	// The link lives in the trailing action column as "graph", the same verb the
	// programs, maps and links tables use for this destination, and opens in its
	// own tab so the roster stays put.
	out := buf.String()
	for _, want := range []string{
		`href="/nodes/node-a/loaders/sg_1000" target="_blank"`,
		`>graph</a>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("loaders index missing %q\n%s", want, out)
		}
	}
	// The label itself is plain text: navigation belongs in the action column.
	if strings.Contains(out, `>loader: agent(1000)</a>`) {
		t.Errorf("group label should not be a link\n%s", out)
	}
	// What a loader is is explained on the column, not in prose above the
	// table - the page carries none, the way the other list pages do not.
	if !strings.Contains(out, "lowest-numbered process holding an fd") {
		t.Errorf("group column does not explain what a loader is\n%s", out)
	}
	// (the tab bar is a <p> too, so this looks for the prose idiom itself)
	if strings.Contains(out, `<p class="muted">`) {
		t.Errorf("loaders index should have no prose above its table\n%s", out)
	}
}

// TestLoadersIndexCounts checks a non-zero maps or links count is the way into
// that tab for the group, and that a zero stays inert - there is nothing behind
// it to open.
func TestLoadersIndexCounts(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data := pageData{
		Node: "node-a", Tab: "loaders",
		Loaders: []loaderSummary{
			{ID: "sg_1000", Label: "loader: agent(1000)", Progs: 2, Maps: 3, Links: 4},
			{ID: "sg_2000", Label: "loader: profiler(2000)", Progs: 1},
		},
	}
	var buf strings.Builder
	if err := h.pages["loaders"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	for _, tab := range []string{"maps", "links"} {
		if !strings.Contains(out, `href="/nodes/node-a/`+tab+`?loader=sg_1000"`) {
			t.Errorf("%s count is not a link to the filtered %s page\n%s", tab, tab, out)
		}
		// Same tab: the filtered list is that page, not an object opened beside
		// the roster, and the page itself carries the way back.
		if strings.Contains(out, `href="/nodes/node-a/`+tab+`?loader=sg_1000" target="_blank"`) {
			t.Errorf("%s count should not open a new tab\n%s", tab, out)
		}
		if strings.Contains(out, `href="/nodes/node-a/`+tab+`?loader=sg_2000"`) {
			t.Errorf("a zero %s count should not be a link\n%s", tab, out)
		}
	}
	// The programs count is not a way in yet: that page has no loader filter.
	if strings.Contains(out, `href="/nodes/node-a/programs?loader=`) {
		t.Errorf("programs count links to a filter the programs page does not have\n%s", out)
	}
}

func TestLoaderGraphRender(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	progs, maps, links := sampleGraphData()
	groups, mapByID := groupByLoader(progs, maps, links, nil)
	data := pageData{
		Node: "node-a", Tab: "loaders",
		GraphLabel: "loader: agent(1000)",
		Mermaid:    buildGroupMermaid(findGroup(groups, "sg_1000"), mapByID, "node-a"),
	}
	var buf strings.Builder
	if err := h.pages["loader"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	// Diagram emitted verbatim (cylinder syntax not HTML-escaped) + renderer.
	if !strings.Contains(out, `map_12[("map 12: m_a (Hash)")]`) {
		t.Errorf("mermaid definition escaped or missing\n%s", out)
	}
	if !strings.Contains(out, "mermaid.initialize") {
		t.Errorf("expected mermaid renderer script\n%s", out)
	}
}

func TestSanitizeLabel(t *testing.T) {
	if got := sanitizeLabel(`a"b[c]d|e<f>g`); strings.ContainsAny(got, `"[]|<>`) {
		t.Errorf("sanitizeLabel left unsafe chars: %q", got)
	}
}

// TestFilterLinksByLoader checks the links page's filter partitions links the
// same way the loaders index counts them - including the fallback that puts a
// link with no reachable program in the no-loader group.
func TestFilterLinksByLoader(t *testing.T) {
	progs, _, _ := sampleGraphData()
	links := []*pb.LinkInfo{
		{Id: 3, Type: "xdp", ProgId: 7},      // agent(1000)
		{Id: 4, Type: "kprobe", ProgId: 8},   // profiler(2000)
		{Id: 5, Type: "tracing", ProgId: 9},  // prog with no loader
		{Id: 6, Type: "struct_ops"},          // no program at all
		{Id: 7, Type: "cgroup", ProgId: 404}, // program the agent did not list
	}

	// The short label: the links page's picker is already called "loader", so
	// the group's own prefix would say the word twice.
	got, label := filterLinksByLoader(progs, links, nil, "sg_1000")
	if label != "agent(1000)" {
		t.Errorf("label = %q, want the short form", label)
	}
	if len(got) != 1 || got[0].GetId() != 3 {
		t.Errorf("sg_1000 links = %+v, want just link 3", got)
	}

	// prog 9 has no loader, so it names the group the same way the index does.
	got, label = filterLinksByLoader(progs, links, nil, unattachedGroupID)
	if label != unattachedLabel {
		t.Errorf("label = %q, want %q", label, unattachedLabel)
	}
	var ids []uint32
	for _, l := range got {
		ids = append(ids, l.GetId())
	}
	if len(ids) != 3 || ids[0] != 5 || ids[1] != 6 || ids[2] != 7 {
		t.Errorf("unattached links = %v, want 5 (loaderless prog), 6 (no prog), 7 (unknown prog)", ids)
	}

	// A group with nothing in it is empty, not everything.
	if got, _ := filterLinksByLoader(progs, links, nil, "sg_9999"); len(got) != 0 {
		t.Errorf("sg_9999 links = %+v, want none", got)
	}
}

// TestFilterLinksByLoaderHonoursHidden is the reason the filter goes through
// loaderGroup rather than progLoader: with a PID hidden, the loaders index
// counts a program under its next holder, and the links page has to agree or a
// count of N will open a list of something else.
func TestFilterLinksByLoaderHonoursHidden(t *testing.T) {
	progs := []*pb.ProgramInfo{{
		Id:   7,
		Pids: []*pb.ProcessRef{{Pid: 1, Comm: "systemd"}, {Pid: 1000, Comm: "agent"}},
	}}
	links := []*pb.LinkInfo{{Id: 3, ProgId: 7}}
	hidden := map[uint32]bool{1: true}

	if got, _ := filterLinksByLoader(progs, links, hidden, "sg_1"); len(got) != 0 {
		t.Errorf("hidden pid 1 still owns links: %+v", got)
	}
	got, label := filterLinksByLoader(progs, links, hidden, "sg_1000")
	if len(got) != 1 || label != "agent(1000)" {
		t.Errorf("links = %+v, label = %q, want link 3 under agent(1000)", got, label)
	}

	// And the counts it must match.
	groups, _ := groupByLoader(progs, nil, links, hidden)
	g := findGroup(groups, "sg_1000")
	if g == nil || len(g.Links) != len(got) {
		t.Errorf("loaders index and links filter disagree: %+v vs %+v", g, got)
	}
}

// TestFilterMapsByLoader checks the maps page's filter partitions maps the same
// way the loaders index counts them: by the programs referencing a map, with the
// maps nobody references or holds left to the no-loader group.
func TestFilterMapsByLoader(t *testing.T) {
	progs, maps, _ := sampleGraphData()
	// A map both loaders' programs reference. Unlike a link, which attaches one
	// program and so sits in one group, this map is in both.
	progs[0].MapIds = []uint32{12, 42}
	progs[1].MapIds = []uint32{13, 42}
	maps = append(maps, &pb.MapInfo{Id: 42, Name: "shared", Type: "Hash"})

	// The short label, for the same reason as the links filter: the page's
	// picker is already called "loader".
	got, label := filterMapsByLoader(progs, maps, nil, "sg_1000")
	if label != "agent(1000)" {
		t.Errorf("label = %q, want the short form", label)
	}
	if ids := mapIDs(got); len(ids) != 2 || ids[0] != 12 || ids[1] != 42 {
		t.Errorf("sg_1000 maps = %v, want 12 (its own) and 42 (shared)", ids)
	}
	got, _ = filterMapsByLoader(progs, maps, nil, "sg_2000")
	if ids := mapIDs(got); len(ids) != 2 || ids[0] != 13 || ids[1] != 42 {
		t.Errorf("sg_2000 maps = %v, want 13 (its own) and 42 (shared)", ids)
	}

	// Prog 9 has no loader and references nothing, so what makes the no-loader
	// group here is the orphan map - and it must not be listed anywhere else.
	got, label = filterMapsByLoader(progs, maps, nil, unattachedGroupID)
	if label != unattachedLabel {
		t.Errorf("label = %q, want %q", label, unattachedLabel)
	}
	if ids := mapIDs(got); len(ids) != 1 || ids[0] != 99 {
		t.Errorf("no-loader maps = %v, want just the orphan 99", ids)
	}

	// A group with nothing in it is empty, not everything.
	if got, _ := filterMapsByLoader(progs, maps, nil, "sg_9999"); len(got) != 0 {
		t.Errorf("sg_9999 maps = %+v, want none", got)
	}

	// And the counts it must match.
	groups, _ := groupByLoader(progs, maps, nil, nil)
	for _, id := range []string{"sg_1000", "sg_2000", unattachedGroupID} {
		g := findGroup(groups, id)
		rows, _ := filterMapsByLoader(progs, maps, nil, id)
		if g == nil || len(g.Maps) != len(rows) {
			t.Errorf("%s: loaders index counts %+v, filter shows %v", id, g, mapIDs(rows))
		}
	}
}

// TestGroupByLoaderMapsWithAKnownLoader is the tetragon shape: a loader whose
// tail-call target nobody holds an fd to. Grouping that target under "no loader"
// is right - nothing on the node says who loaded it - but its maps must not
// follow it there when the node plainly says whose they are, or one loaderless
// program drags its loader's whole map set into the residual bucket.
func TestGroupByLoaderMapsWithAKnownLoader(t *testing.T) {
	tetragon := []*pb.ProcessRef{{Pid: 10304, Comm: "tetragon"}}
	progs := []*pb.ProgramInfo{
		{Id: 475, Name: "event_execve", MapIds: []uint32{87, 213}, Pids: tetragon},
		{Id: 476, Name: "execve_send", MapIds: []uint32{87, 213, 209}}, // tail-call target: no holder
	}
	maps := []*pb.MapInfo{
		{Id: 82, Name: "policy_filter_map", Pids: tetragon}, // held, referenced by nobody
		{Id: 87, Name: "execve_map", Pids: tetragon},        // held and referenced
		{Id: 209, Name: "throttle_heap_map"},                // only the loaderless program's
		{Id: 213, Name: ".rodata"},                          // unheld, but a held program uses it
	}
	groups, _ := groupByLoader(progs, maps, nil, nil)

	tg := findGroup(groups, "sg_10304")
	if tg == nil {
		t.Fatalf("missing tetragon group: %+v", groups)
	}
	if got := tg.Maps; len(got) != 3 || got[0] != 87 || got[1] != 213 || got[2] != 82 {
		t.Errorf("tetragon maps = %v, want 87, 213 (referenced) and 82 (held only)", got)
	}

	un := findGroup(groups, unattachedGroupID)
	if un == nil || len(un.Progs) != 1 || un.Progs[0].GetId() != 476 {
		t.Fatalf("no-loader progs = %+v, want just the tail-call target 476", un)
	}
	if got := un.Maps; len(got) != 1 || got[0] != 209 {
		t.Errorf("no-loader maps = %v, want just 209 - the one nothing else claims", got)
	}

	// And the rows the maps page shows for each, which cannot disagree with it.
	for _, id := range []string{"sg_10304", unattachedGroupID} {
		g := findGroup(groups, id)
		rows, _ := filterMapsByLoader(progs, maps, nil, id)
		if len(g.Maps) != len(rows) {
			t.Errorf("%s: loaders index counts %v, filter shows %v", id, g.Maps, mapIDs(rows))
		}
	}
}

// TestGroupByLoaderHeldMapIsNotAnOrphan: a map no program references is not
// automatically loaderless - a loader holding an fd to one it has not wired up
// yet is named right there in the maps page's Holders column.
func TestGroupByLoaderHeldMapIsNotAnOrphan(t *testing.T) {
	maps := []*pb.MapInfo{
		{Id: 61, Name: "iter_auxiliary", Pids: []*pb.ProcessRef{{Pid: 8347, Comm: "falco"}}},
		{Id: 99, Name: "orphan"},
	}
	groups, _ := groupByLoader(nil, maps, nil, nil)

	falco := findGroup(groups, "sg_8347")
	if falco == nil || falco.Label != "loader: falco(8347)" {
		t.Fatalf("missing/mislabelled falco group: %+v", groups)
	}
	if got := falco.Maps; len(got) != 1 || got[0] != 61 {
		t.Errorf("falco maps = %v, want [61]", got)
	}
	if got := findGroup(groups, unattachedGroupID).Maps; len(got) != 1 || got[0] != 99 {
		t.Errorf("no-loader maps = %v, want just the unheld orphan 99", got)
	}

	// The label comes from the holder, so a group with no programs in it still
	// names itself rather than falling back to the URL's bare pid.
	if _, label := filterMapsByLoader(nil, maps, nil, "sg_8347"); label != "falco(8347)" {
		t.Errorf("label = %q, want falco(8347)", label)
	}

	// A hidden holder is hidden here too, the same as it is for a program.
	groups, _ = groupByLoader(nil, maps, nil, map[uint32]bool{8347: true})
	if findGroup(groups, "sg_8347") != nil {
		t.Errorf("hidden pid 8347 still owns maps: %+v", groups)
	}
	if got := findGroup(groups, unattachedGroupID).Maps; len(got) != 2 {
		t.Errorf("no-loader maps = %v, want both once the holder is hidden", got)
	}
}

// TestFilterMapsByLoaderHonoursHidden is the reason a referenced map is grouped
// by its programs' loaders and not by its own holder PIDs: with a PID hidden,
// the loaders index counts a program under its next holder, and the maps page
// has to agree or a count of N will open a list of something else.
func TestFilterMapsByLoaderHonoursHidden(t *testing.T) {
	progs := []*pb.ProgramInfo{{
		Id:     7,
		MapIds: []uint32{12},
		Pids:   []*pb.ProcessRef{{Pid: 1, Comm: "systemd"}, {Pid: 1000, Comm: "agent"}},
	}}
	maps := []*pb.MapInfo{{Id: 12, Name: "m_a"}}
	hidden := map[uint32]bool{1: true}

	if got, _ := filterMapsByLoader(progs, maps, hidden, "sg_1"); len(got) != 0 {
		t.Errorf("hidden pid 1 still owns maps: %+v", got)
	}
	got, label := filterMapsByLoader(progs, maps, hidden, "sg_1000")
	if len(got) != 1 || label != "agent(1000)" {
		t.Errorf("maps = %v, label = %q, want map 12 under agent(1000)", mapIDs(got), label)
	}
	// A map its program owns is not also an orphan.
	if got, _ := filterMapsByLoader(progs, maps, hidden, unattachedGroupID); len(got) != 0 {
		t.Errorf("no-loader maps = %v, want none", mapIDs(got))
	}
}

func mapIDs(maps []*pb.MapInfo) []uint32 {
	var ids []uint32
	for _, m := range maps {
		ids = append(ids, m.GetId())
	}
	return ids
}

func TestParseLoaderGroup(t *testing.T) {
	for _, tc := range []struct {
		group string
		label string
		ok    bool
	}{
		{"sg_1234", "pid 1234", true},
		{unattachedGroupID, unattachedLabel, true},
		{"1234", "", false},
		{"sg_", "", false},
		{"sg_nope", "", false},
		{"sg_-1", "", false},
		{"", "", false},
	} {
		label, ok := parseLoaderGroup(tc.group)
		if ok != tc.ok || label != tc.label {
			t.Errorf("parseLoaderGroup(%q) = %q, %v; want %q, %v", tc.group, label, ok, tc.label, tc.ok)
		}
	}
}

// TestLinkLoaderChoices checks the links page's picker offers exactly the groups
// that have links, counted as the loaders index counts them.
func TestLinkLoaderChoices(t *testing.T) {
	progs, _, _ := sampleGraphData()
	links := []*pb.LinkInfo{
		{Id: 3, ProgId: 7}, // agent(1000)
		{Id: 4, ProgId: 7}, // agent(1000) again
		{Id: 5},            // no program: the no-loader group
	}

	got := linkLoaderChoices(progs, links, nil)
	want := []loaderChoice{
		{Group: "sg_1000", Label: "agent(1000)", Count: 2},
		{Group: unattachedGroupID, Label: unattachedLabel, Count: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("choices = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("choice %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// profiler(2000) loaded a program but nothing attaches it, so narrowing the
	// links page to it is a question with a known answer - it is not offered.
	if hasLoaderChoice(got, "sg_2000") {
		t.Errorf("a group with no links should not be offered: %+v", got)
	}

	// And with no links at all there is nothing to narrow.
	if got := linkLoaderChoices(progs, nil, nil); len(got) != 0 {
		t.Errorf("choices with no links = %+v, want none", got)
	}
}

// TestLoaderChoicesMatchIndexCounts pins the picker to the loaders index: both
// go through groupByLoader, so a count offered here is the count shown there.
func TestLinkLoaderChoicesMatchIndexCounts(t *testing.T) {
	progs, maps, links := sampleGraphData()
	groups, _ := groupByLoader(progs, maps, links, nil)
	for _, c := range linkLoaderChoices(progs, links, nil) {
		g := findGroup(groups, c.Group)
		if g == nil {
			t.Errorf("picker offers %q, which the loaders index does not group", c.Group)
			continue
		}
		if len(g.Links) != c.Count {
			t.Errorf("%s: picker says %d links, index says %d", c.Group, c.Count, len(g.Links))
		}
		if shortLoaderLabel(g.Label) != c.Label {
			t.Errorf("%s: picker label %q, index label %q", c.Group, c.Label, g.Label)
		}
	}
}

// TestMapLoaderChoices checks the maps page's picker offers exactly the groups
// that have maps, counted as the loaders index counts them.
func TestMapLoaderChoices(t *testing.T) {
	progs, maps, _ := sampleGraphData()

	got := mapLoaderChoices(progs, maps, nil)
	want := []loaderChoice{
		{Group: "sg_1000", Label: "agent(1000)", Count: 1},
		{Group: "sg_2000", Label: "profiler(2000)", Count: 1},
		// Prog 9 loaded no maps; the orphan is what puts this group in the list.
		{Group: unattachedGroupID, Label: unattachedLabel, Count: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("choices = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("choice %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// A loader whose programs reference no map is not offered: narrowing the
	// maps page to it is a question with a known answer.
	progs, maps, _ = sampleGraphData()
	progs[0].MapIds = nil
	if hasLoaderChoice(mapLoaderChoices(progs, maps, nil), "sg_1000") {
		t.Errorf("a group with no maps should not be offered")
	}

	// And with nothing on the node there is nothing to narrow.
	if got := mapLoaderChoices(nil, nil, nil); len(got) != 0 {
		t.Errorf("choices with no objects = %+v, want none", got)
	}
}

// TestMapLoaderChoicesMatchIndexCounts pins that picker to the loaders index the
// way TestLinkLoaderChoicesMatchIndexCounts pins the links one.
func TestMapLoaderChoicesMatchIndexCounts(t *testing.T) {
	progs, maps, links := sampleGraphData()
	groups, _ := groupByLoader(progs, maps, links, nil)
	for _, c := range mapLoaderChoices(progs, maps, nil) {
		g := findGroup(groups, c.Group)
		if g == nil {
			t.Errorf("picker offers %q, which the loaders index does not group", c.Group)
			continue
		}
		if len(g.Maps) != c.Count {
			t.Errorf("%s: picker says %d maps, index says %d", c.Group, c.Count, len(g.Maps))
		}
		if shortLoaderLabel(g.Label) != c.Label {
			t.Errorf("%s: picker label %q, index label %q", c.Group, c.Label, g.Label)
		}
	}
}

// TestShortLoaderLabel checks the two spellings stay in step: the loaders index
// keeps the prefix that tells a loader from the no-loader row, and everything
// under a field already called "loader" drops it.
func TestShortLoaderLabel(t *testing.T) {
	progs, _, _ := sampleGraphData()
	_, label := loaderGroup(progs[0], nil)
	if label != "loader: agent(1000)" {
		t.Errorf("index label = %q, want the prefixed form", label)
	}
	if got := shortLoaderLabel(label); got != "agent(1000)" {
		t.Errorf("short label = %q, want the prefix dropped", got)
	}
	// The no-loader group carries no prefix and must survive untouched.
	if got := shortLoaderLabel(unattachedLabel); got != unattachedLabel {
		t.Errorf("short label = %q, want %q unchanged", got, unattachedLabel)
	}
}

// TestGroupByLoaderPutsNoLoaderLast checks the residual group sorts last however
// early it is created. Groups are otherwise in first-seen order over programs
// sorted by id, so a holderless program with the lowest id used to put the
// no-loader group at the top of the roster, between real loaders.
func TestGroupByLoaderPutsNoLoaderLast(t *testing.T) {
	progs := []*pb.ProgramInfo{
		{Id: 1, Name: "p_orphan"}, // no holder: the no-loader group, created first
		{Id: 2, Name: "p_a", Pids: []*pb.ProcessRef{{Pid: 1000, Comm: "agent"}}},
		{Id: 3, Name: "p_b", Pids: []*pb.ProcessRef{{Pid: 2000, Comm: "profiler"}}},
	}
	groups, _ := groupByLoader(progs, nil, nil, nil)

	var ids []string
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	want := []string{"sg_1000", "sg_2000", unattachedGroupID}
	if len(ids) != len(want) {
		t.Fatalf("group order = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("group order = %v, want %v", ids, want)
		}
	}

	// The pickers are built from the same partition, so they end with it too.
	choices := linkLoaderChoices(progs, []*pb.LinkInfo{{Id: 3, ProgId: 1}, {Id: 4, ProgId: 2}}, nil)
	if len(choices) == 0 || choices[len(choices)-1].Group != unattachedGroupID {
		t.Errorf("picker = %+v, want the no-loader group last", choices)
	}
}

// TestLoaderRosterSplitsNoLoader checks the loaders index gets the residual
// group apart from the loaders: the roster above the rule is processes only, so
// the count in the heading over it counts loaders and nothing else.
func TestLoaderRosterSplitsNoLoader(t *testing.T) {
	progs, maps, links := sampleGraphData()
	groups, _ := groupByLoader(progs, maps, links, nil)
	loaders, noLoader := loaderRoster(groups)

	if len(loaders) != 2 || loaders[0].ID != "sg_1000" || loaders[1].ID != "sg_2000" {
		t.Errorf("roster = %+v, want the two loaders only", loaders)
	}
	if noLoader == nil {
		t.Fatal("no-loader group missing from the roster")
	}
	if noLoader.ID != unattachedGroupID || noLoader.Label != unattachedLabel {
		t.Errorf("no-loader row = %+v, want %q/%q", noLoader, unattachedGroupID, unattachedLabel)
	}
	// Prog 9 has no holder, and map 99 is referenced by nobody.
	if noLoader.Progs != 1 || noLoader.Maps != 1 {
		t.Errorf("no-loader row = %+v, want 1 program and 1 map", noLoader)
	}

	// A node where everything has a loader has no residual row at all.
	progs[2].Pids = []*pb.ProcessRef{{Pid: 1000, Comm: "agent"}}
	maps = maps[:2]
	groups, _ = groupByLoader(progs, maps, links, nil)
	if _, noLoader := loaderRoster(groups); noLoader != nil {
		t.Errorf("no-loader row = %+v, want none when every object has a loader", noLoader)
	}
}

// TestLoadersIndexResidualRow checks the no-loader group is rendered as the
// residual row - marked for the rule that sets it below the loaders, and out of
// the heading's count - while staying a live row: its counts still open the
// filtered page behind them.
func TestLoadersIndexResidualRow(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data := pageData{
		Node: "node-a", Tab: "loaders",
		Loaders:  []loaderSummary{{ID: "sg_1000", Label: "loader: agent(1000)", Progs: 2, Maps: 3, Links: 1}},
		NoLoader: &loaderSummary{ID: unattachedGroupID, Label: unattachedLabel, Progs: 1, Maps: 2},
	}
	var buf strings.Builder
	if err := h.pages["loaders"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, `<tr class="residual">`) {
		t.Errorf("no-loader group is not marked as the residual row\n%s", out)
	}
	if !strings.Contains(out, `href="/nodes/node-a/maps?loader=`+unattachedGroupID+`"`) {
		t.Errorf("residual row's maps count is not a link to the filtered page\n%s", out)
	}
	if !strings.Contains(out, `href="/nodes/node-a/loaders/`+unattachedGroupID+`"`) {
		t.Errorf("residual row has no graph link\n%s", out)
	}
	// One loader, so the heading counts one - the residual group is not a loader.
	if !strings.Contains(out, "loaders on node-a") || !strings.Contains(out, ">(1)<") {
		t.Errorf("heading should count the 1 loader, not the residual group\n%s", out)
	}

	// With nothing but the residual group the roster is empty, and the empty
	// state must not claim the node has no eBPF objects - it has some.
	data.Loaders = nil
	buf.Reset()
	if err := h.pages["loaders"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out := buf.String(); strings.Contains(out, "(no eBPF objects)") {
		t.Errorf("empty roster with a residual group should not say the node is empty\n%s", out)
	}

	// And an empty node says exactly that.
	data.NoLoader = nil
	buf.Reset()
	if err := h.pages["loaders"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "(no eBPF objects)") {
		t.Errorf("empty node should say so\n%s", out)
	}
}
