package web

import (
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// TestProcessRefFormatIsConsistent pins the single spelling for a process
// reference, "comm(pid)", across every place one is rendered. These drifted
// apart once - progLoader and the graph group labels grew a space that the
// programs and maps tables never had - because no test looked at the string.
func TestProcessRefFormatIsConsistent(t *testing.T) {
	progs := []*pb.ProgramInfo{{
		Id: 7, Name: "p_a", MapIds: []uint32{12},
		Pids: []*pb.ProcessRef{{Pid: 1000, Comm: "agent"}},
	}}

	if got, want := progLoader(progs, 7), "agent(1000)"; got != want {
		t.Errorf("progLoader = %q, want %q", got, want)
	}

	groups, _ := groupByLoader(progs, nil, nil, nil)
	if len(groups) != 1 {
		t.Fatalf("groupByLoader returned %d groups, want 1", len(groups))
	}
	if got, want := groups[0].Label, "loader: agent(1000)"; got != want {
		t.Errorf("group label = %q, want %q", got, want)
	}

	// mapLoaders renders the inferred loader of a map nothing holds an fd to.
	got := mapLoaders(progs, 12)
	if len(got) != 1 || got[0] != "agent(1000) via prog 7" {
		t.Errorf("mapLoaders = %v, want [\"agent(1000) via prog 7\"]", got)
	}
}
