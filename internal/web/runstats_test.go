package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

func TestRunTime(t *testing.T) {
	for ns, want := range map[uint64]string{
		0:             "0ns",
		512:           "512ns",
		3_412:         "3.41µs",
		12_040_000:    "12.0ms",
		123_400_000:   "123ms",
		1_523_000_000: "1.52s",
		7_200e9:       "7200s",
	} {
		if got := runTime(ns); got != want {
			t.Errorf("runTime(%d) = %q, want %q", ns, got, want)
		}
	}
}

func TestStatsOffIn(t *testing.T) {
	for s, want := range map[uint32]string{1: "off in 1 min", 60: "off in 1 min", 61: "off in 2 min", 600: "off in 10 min"} {
		if got := statsOffIn(s); got != want {
			t.Errorf("statsOffIn(%d) = %q, want %q", s, got, want)
		}
	}
}

func renderPrograms(t *testing.T, stats *pb.StatsState) string {
	t.Helper()
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data := pageData{
		Node:  "node-a",
		Tab:   "programs",
		Stats: stats,
		Programs: []*pb.ProgramInfo{
			{Id: 7, Name: "xdp_prog", Type: "XDP", RunCount: 1200, RunTimeNs: 3_600_000, RecursionMisses: 2},
			{Id: 8, Name: "idle", Type: "Kprobe"},
		},
	}
	var buf bytes.Buffer
	if err := h.pages["programs"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	return buf.String()
}

// An agent that predates the switch reports no state: the page is the one it
// always was.
func TestProgramsStatsHiddenForOldAgent(t *testing.T) {
	out := renderPrograms(t, nil)
	for _, s := range []string{">Runs</th>", "run stats", "/programs/stats"} {
		if strings.Contains(out, s) {
			t.Errorf("page should not carry %q", s)
		}
	}
}

func TestProgramsStatsToggleOff(t *testing.T) {
	out := renderPrograms(t, &pb.StatsState{})
	if !strings.Contains(out, `action="/nodes/node-a/programs/stats"`) {
		t.Errorf("toggle form missing\n%s", out)
	}
	if !strings.Contains(out, `role="switch"`) {
		t.Errorf("toggle should be a switch\n%s", out)
	}
	if strings.Contains(out, " checked") || strings.Contains(out, ">Runs</th>") {
		t.Errorf("stats off: unchecked toggle and no columns\n%s", out)
	}
}

func TestProgramsStatsColumns(t *testing.T) {
	out := renderPrograms(t, &pb.StatsState{Held: true, SecondsLeft: 540})
	for _, s := range []string{">Runs</th>", ">Run time</th>", ">Avg/run</th>", "off in 9 min", `value="1" checked`} {
		if !strings.Contains(out, s) {
			t.Errorf("page should carry %q\n%s", s, out)
		}
	}
	row := programsRow(t, out, "7")
	for _, s := range []string{`<td class="num">1,200<span`, "+2 missed", `<td class="num">3.60ms</td>`, `<td class="num">3.00µs</td>`} {
		if !strings.Contains(row, s) {
			t.Errorf("program 7's row should carry %q\n%s", s, row)
		}
	}
	// A program that never ran shows zero runs, and no run time or average.
	idle := programsRow(t, out, "8")
	if !strings.Contains(idle, `<span class="muted">0</span>`) || strings.Count(idle, `<span class="muted">-</span>`) < 2 {
		t.Errorf("idle program's row\n%s", idle)
	}
}

// Stats kept on by someone else: the columns show, and the toggle cannot
// claim to turn them off.
func TestProgramsStatsLocked(t *testing.T) {
	out := renderPrograms(t, &pb.StatsState{Holders: []*pb.ProcessRef{{Pid: 100, Comm: "bpftop"}}})
	if !strings.Contains(out, ">Runs</th>") {
		t.Errorf("stats on elsewhere should still show the columns\n%s", out)
	}
	if !strings.Contains(out, "checked disabled") || !strings.Contains(out, "bpftop(100)") {
		t.Errorf("locked toggle should be disabled and name who keeps it on\n%s", out)
	}
	if strings.Contains(out, `name="on"`) {
		t.Errorf("a locked toggle must submit nothing\n%s", out)
	}

	out = renderPrograms(t, &pb.StatsState{Sysctl: true})
	if !strings.Contains(out, ">Runs</th>") || !strings.Contains(out, "kernel.bpf_stats_enabled=1") {
		t.Errorf("sysctl on: want columns and the sysctl named\n%s", out)
	}
}

// programsRow returns the rendered programs-list row for a program id.
func programsRow(t *testing.T, out, id string) string {
	t.Helper()
	for _, row := range strings.Split(out, "<tr>") {
		if strings.Contains(row, "<td>"+id+"</td>") {
			return row
		}
	}
	t.Fatalf("no row for program %s\n%s", id, out)
	return ""
}

// The toggle is the one route that changes a node, so a form another site
// posts through the viewer's browser must not reach the agent.
func TestSetStatsRefusesCrossOrigin(t *testing.T) {
	h, err := New(fakeDisc{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-a/programs/stats", strings.NewReader("on=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: status %d, want 403", rec.Code)
	}
}
