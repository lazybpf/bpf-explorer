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
	if out := buf.String(); !strings.Contains(out, `href="/nodes/node-a/loaders/sg_1000"`) {
		t.Errorf("loaders index missing loader link\n%s", out)
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
