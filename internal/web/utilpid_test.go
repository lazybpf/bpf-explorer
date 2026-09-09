package web

import (
	"regexp"
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// TestUtilPidPageEmpty checks the page offers its lookup before one has been
// asked for, and claims nothing about a process it has not looked up.
func TestUtilPidPageEmpty(t *testing.T) {
	out := renderUtilPid(t, &pidLookup{})

	for _, want := range []string{
		`name="pid"`,
		`action="/nodes/node-a/utils/pid"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
	// One field, and the cursor is in it.
	if !regexp.MustCompile(`<input[^>]*name="pid"[^>]*autofocus`).MatchString(out) {
		t.Errorf("expected the pid field to take the focus\n%s", out)
	}
	if strings.Contains(out, "No process") {
		t.Errorf("page reported a miss without a lookup having run\n%s", out)
	}
}

func TestUtilPid(t *testing.T) {
	out := renderUtilPid(t, &pidLookup{
		PID: "1234",
		Process: &pb.DescribeProcessResponse{
			Found: true, Pid: 1234, Comm: "trace_loader", State: "S (sleeping)",
			Ppid: 1, Uid: "0", Cmdline: "./loader --verbose",
			Exe: "/usr/local/bin/loader", Cgroup: "/kubepods.slice/pod0ddf.slice",
		},
		Parent: &pb.DescribeProcessResponse{
			Found: true, Pid: 1, Comm: "systemd", Cmdline: "/sbin/init splash",
		},
	})

	for _, want := range []string{"trace_loader", "S (sleeping)", "./loader --verbose",
		"/usr/local/bin/loader", "/kubepods.slice/pod0ddf.slice"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
	// The parent came back with the process: named, described, and one click
	// away rather than another number to type in.
	for _, want := range []string{
		"systemd(1)",
		"/sbin/init splash",
		`href="/nodes/node-a/utils/pid?pid=1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the parent's %q on the page\n%s", want, out)
		}
	}

	// A pid that is gone is the common case for a number read out of a map, and
	// must not look like a failure.
	gone := renderUtilPid(t, &pidLookup{PID: "1234", Process: &pb.DescribeProcessResponse{Found: false}})
	if !strings.Contains(gone, "No process <code>1234</code>") {
		t.Errorf("expected the page to say the pid is gone\n%s", gone)
	}
}

// TestUtilPidNSPid checks the pid row carries the number the process goes by
// inside its container, which is the one anything run in there reports.
func TestUtilPidNSPid(t *testing.T) {
	out := renderUtilPid(t, &pidLookup{
		PID: "4711",
		Process: &pb.DescribeProcessResponse{
			Found: true, Pid: 4711, Comm: "nginx", NsPids: []uint32{4711, 1},
		},
	})
	if !strings.Contains(out, "1 in its pid namespace") {
		t.Errorf("expected the in-container pid on the page\n%s", out)
	}

	// A process in the agent's own pid namespace goes by one number, and the
	// page has nothing to add to the one it was asked about.
	host := renderUtilPid(t, &pidLookup{
		PID: "4711",
		Process: &pb.DescribeProcessResponse{
			Found: true, Pid: 4711, Comm: "sshd", NsPids: []uint32{4711},
		},
	})
	if strings.Contains(host, "in its pid namespace") {
		t.Errorf("nothing to say about a pid that is the same inside\n%s", host)
	}
}

func TestInnerPIDs(t *testing.T) {
	tests := []struct {
		name string
		pids []uint32
		want string
	}{
		{"container init", []uint32{4711, 1}, "1"},
		{"nested", []uint32{4711, 812, 1}, "812 -> 1"},
		{"same inside", []uint32{4711}, ""},
		{"not reported", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := innerPIDs(tc.pids); got != tc.want {
				t.Errorf("innerPIDs(%v) = %q, want %q", tc.pids, got, tc.want)
			}
		})
	}
}

// TestUtilPidNamespaces checks the page places a process among the namespaces a
// container is built from: every kind listed by its number, and the ones that
// are not init's marked as the process's own.
func TestUtilPidNamespaces(t *testing.T) {
	out := renderUtilPid(t, &pidLookup{
		PID: "1234",
		Process: &pb.DescribeProcessResponse{
			Found: true, Pid: 1234, Comm: "nginx",
			Namespaces: []*pb.Namespace{
				{Kind: "net", Inode: 4026532345, Pid1Inode: 4026531840},
				{Kind: "uts", Inode: 4026531838, Pid1Inode: 4026531838},
			},
		},
	})

	for _, want := range []string{"net", "4026532345", "uts", "4026531838"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
	if !strings.Contains(out, `<span class="badge"`) {
		t.Errorf("a namespace that is not pid 1's should be marked as the process's own\n%s", out)
	}
	if !strings.Contains(out, "shared with pid 1") {
		t.Errorf("a namespace pid 1 is in too should say so\n%s", out)
	}

	// Nothing was compared - this is pid 1 itself, or init's links were not
	// readable - so the page marks neither way rather than implying a container.
	uncompared := renderUtilPid(t, &pidLookup{
		PID: "1",
		Process: &pb.DescribeProcessResponse{
			Found: true, Pid: 1, Comm: "systemd",
			Namespaces: []*pb.Namespace{{Kind: "net", Inode: 4026531840}},
		},
	})
	if strings.Contains(uncompared, `<span class="badge"`) || strings.Contains(uncompared, "shared with pid 1") {
		t.Errorf("an unmade comparison must not be reported either way\n%s", uncompared)
	}

	// An agent that cannot read /proc/<pid>/ns has no namespaces to show, and
	// the section is left out rather than shown empty.
	none := renderUtilPid(t, &pidLookup{
		PID: "1234", Process: &pb.DescribeProcessResponse{Found: true, Pid: 1234, Comm: "nginx"},
	})
	if strings.Contains(none, "namespaces") {
		t.Errorf("no namespaces were read, so nothing is claimed about them\n%s", none)
	}
}

// TestUtilPidParentUnknown covers the parent lookups that answer nothing: the
// row still links onwards, and says which kind of nothing it got.
func TestUtilPidParentUnknown(t *testing.T) {
	process := func(ppid uint32) *pb.DescribeProcessResponse {
		return &pb.DescribeProcessResponse{Found: true, Pid: 1234, Comm: "loader", Ppid: ppid}
	}

	// The parent exited between the two reads.
	gone := renderUtilPid(t, &pidLookup{
		PID: "1234", Process: process(4242),
		Parent: &pb.DescribeProcessResponse{Found: false},
	})
	if !strings.Contains(gone, "?(4242)") {
		t.Errorf("a parent with no name still links by number\n%s", gone)
	}
	if !strings.Contains(gone, "exited between the two reads") {
		t.Errorf("expected the page to say why the parent has no detail\n%s", gone)
	}

	// The parent was never asked about, because asking failed.
	unasked := renderUtilPid(t, &pidLookup{PID: "1234", Process: process(4242)})
	if !strings.Contains(unasked, "?(4242)") {
		t.Errorf("the ppid links onwards whether or not it could be described\n%s", unasked)
	}
	if strings.Contains(unasked, "exited between the two reads") {
		t.Errorf("nothing was learned about the parent, so nothing is claimed\n%s", unasked)
	}

	// Pid 0 is the kernel's own ancestor: there is nowhere to go from here.
	kernel := renderUtilPid(t, &pidLookup{PID: "2", Process: process(0)})
	if strings.Contains(kernel, "pid=0") {
		t.Errorf("a process with no parent should not link to pid 0\n%s", kernel)
	}
}

func TestParentComm(t *testing.T) {
	tests := []struct {
		name string
		look pidLookup
		want string
	}{
		{"named", pidLookup{Parent: &pb.DescribeProcessResponse{Found: true, Comm: "bash"}}, "bash"},
		{"gone", pidLookup{Parent: &pb.DescribeProcessResponse{Found: false}}, "?"},
		{"nameless", pidLookup{Parent: &pb.DescribeProcessResponse{Found: true}}, "?"},
		{"never asked", pidLookup{}, "?"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.look.ParentComm(); got != tt.want {
				t.Errorf("ParentComm() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestUtilPidTitle keeps a row of lookup tabs navigable: each one is named by
// what was asked of it, and by the utility itself before anything was.
func TestUtilPidTitle(t *testing.T) {
	tests := []struct {
		name string
		look *pidLookup
		want string
	}{
		{"asked", &pidLookup{PID: "1234"}, "pid 1234 - node-a - bpf-explorer"},
		{"nothing asked", &pidLookup{}, "pid lookup - node-a - bpf-explorer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pageTitle("utilpid", pageData{Node: "node-a", PIDLookup: tc.look})
			if got != tc.want {
				t.Errorf("pageTitle = %q, want %q", got, tc.want)
			}
		})
	}
}

func renderUtilPid(t *testing.T, look *pidLookup) string {
	t.Helper()
	return renderUtil(t, "utilpid", pageData{Node: "node-a", Tab: "utils", Util: "pid", PIDLookup: look})
}
