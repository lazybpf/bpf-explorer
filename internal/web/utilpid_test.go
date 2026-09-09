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
