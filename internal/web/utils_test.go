package web

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

func TestParseInode(t *testing.T) {
	tests := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{in: "1179921", want: 1179921},
		{in: "0x120051", want: 0x120051}, // as a map dump prints it
		{in: "0X120051", want: 0x120051},
		// Base 10 is not inferred: "0755" is the inode seven hundred and
		// fifty-five, not 493, however Go's base-0 parsing would read it.
		{in: "0755", want: 755},
		{in: "0", wantErr: true}, // /proc's placeholder for "no file"
		{in: "-1", wantErr: true},
		{in: "42abc", wantErr: true},
		{in: "abc", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseInode(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseInode(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("parseInode(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestValidDevice(t *testing.T) {
	for _, in := range []string{"253:1", "0:0", "8:2"} {
		if !validDevice(in) {
			t.Errorf("validDevice(%q) = false, want true", in)
		}
	}
	// Hex is what /proc/<pid>/maps prints, but every device this page shows is
	// decimal, so accepting "fd:01" would silently look for the wrong device.
	for _, in := range []string{"fd:01", "253", "253:", ":1", "", "253:1:2", "-1:0"} {
		if validDevice(in) {
			t.Errorf("validDevice(%q) = true, want false", in)
		}
	}
}

// TestUtilsPageEmpty checks the page offers both lookups before either has been
// asked for, and claims nothing about results it has not searched for.
func TestUtilsPageEmpty(t *testing.T) {
	out := renderUtils(t, pageData{Node: "node-a", Tab: "utils", Lookup: &lookupView{}})

	for _, want := range []string{
		`name="inode"`,
		`name="dev"`,
		`name="pid"`,
		`action="/nodes/node-a/utils"`,
		`<a class="active" href="/nodes/node-a/utils">`, // its own tab
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "Nothing holds inode") {
		t.Error("page reported a miss without a lookup having run")
	}
}

// TestUtilsInodeMatches renders the answer: the path, where it lives, and every
// holder - grouped under one path rather than repeated per process.
func TestUtilsInodeMatches(t *testing.T) {
	out := renderUtils(t, pageData{
		Node: "node-a",
		Tab:  "utils",
		Lookup: &lookupView{
			Inode:    "1179921",
			Searched: true,
			Scanned:  312,
			Matches: []*pb.InodeMatch{{
				Path:   "/usr/sbin/nginx",
				Device: "253:1",
				Mount:  "/",
				Holders: []*pb.InodeHolder{
					{Pid: 2000, Comm: "nginx", Source: "map"},
					{Pid: 2001, Comm: "logger", Source: "fd", Fd: "7"},
				},
			}},
		},
	})

	for _, want := range []string{
		"/usr/sbin/nginx",
		"253:1",
		"nginx(2000)",
		"mapped",
		"logger(2001)",
		"fd 7",
		// A holder links to its own description, keeping the inode lookup.
		`href="/nodes/node-a/utils?inode=1179921&dev=&pid=2000"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
}

// TestUtilsManyHoldersAreCapped keeps the path readable: libc is mapped by
// nearly every process on a node, and a cell listing all of them buries the
// answer it belongs to.
func TestUtilsManyHoldersAreCapped(t *testing.T) {
	all := make([]*pb.InodeHolder, 0, 99)
	for pid := 1; pid <= 99; pid++ {
		all = append(all, &pb.InodeHolder{Pid: uint32(pid), Comm: "proc", Source: "map"})
	}
	if got := holders(all); len(got.Head) != maxHolders || got.More != 99-maxHolders {
		t.Errorf("holders(99) = %d shown, %d more; want %d and %d",
			len(got.Head), got.More, maxHolders, 99-maxHolders)
	}
	if got := holders(all[:3]); len(got.Head) != 3 || got.More != 0 {
		t.Errorf("holders(3) = %d shown, %d more; want all three and none held back",
			len(got.Head), got.More)
	}

	out := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{Inode: "42", Searched: true, Scanned: 300,
			Matches: []*pb.InodeMatch{{Path: "/lib/libc.so.6", Device: "8:2", Holders: all}}}})
	if !strings.Contains(out, "and 91 more, 99 in all") {
		t.Errorf("expected the held-back holders to be counted\n%s", out)
	}
	if strings.Contains(out, "proc(99)") {
		t.Error("holder 99 is past the cap and should not be rendered")
	}
}

// TestUtilsInodeMissDistinguishesNothingSearched is the honesty the page turns
// on: "nothing holds it" and "nothing was searched" are different answers, and
// only the first one is about the inode.
func TestUtilsInodeMissDistinguishesNothingSearched(t *testing.T) {
	searched := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{Inode: "42", Searched: true, Scanned: 312}})
	if !strings.Contains(searched, "Nothing holds inode") {
		t.Errorf("a real miss should say nothing holds it\n%s", searched)
	}
	if !strings.Contains(searched, "312 processes") {
		t.Errorf("a miss should say how much was searched\n%s", searched)
	}

	blind := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{Inode: "42", Searched: true, Scanned: 0}})
	if !strings.Contains(blind, "No processes were searched") {
		t.Errorf("an unsearchable /proc must not read as a miss\n%s", blind)
	}
	if strings.Contains(blind, "Nothing holds inode") {
		t.Errorf("nothing was searched, so nothing can be concluded\n%s", blind)
	}
}

// TestUtilsInodeInAnotherNamespace covers the container case: the holder's path
// is not the agent's, so the reachable form has to be shown too.
func TestUtilsInodeInAnotherNamespace(t *testing.T) {
	out := renderUtils(t, pageData{
		Node: "node-a",
		Tab:  "utils",
		Lookup: &lookupView{
			Inode: "42", Searched: true, Scanned: 9,
			Matches: []*pb.InodeMatch{{
				Path:     "/app/config.yaml",
				Device:   "0:52",
				Deleted:  true,
				HostPath: "/proc/8123/root/app/config.yaml",
				Holders:  []*pb.InodeHolder{{Pid: 8123, Comm: "app", Source: "fd", Fd: "3"}},
			}},
		},
	})

	for _, want := range []string{"/proc/8123/root/app/config.yaml", "another mount namespace", "deleted"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
}

func TestUtilsProcess(t *testing.T) {
	out := renderUtils(t, pageData{
		Node: "node-a",
		Tab:  "utils",
		Lookup: &lookupView{
			PID: "1234",
			Process: &pb.DescribeProcessResponse{
				Found: true, Pid: 1234, Comm: "trace_loader", State: "S (sleeping)",
				Ppid: 1, Uid: "0", Cmdline: "./loader --verbose",
				Exe: "/usr/local/bin/loader", Cgroup: "/kubepods.slice/pod0ddf.slice",
			},
			Parent: &pb.DescribeProcessResponse{
				Found: true, Pid: 1, Comm: "systemd", Cmdline: "/sbin/init splash",
			},
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
		`href="/nodes/node-a/utils?inode=&dev=&pid=1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the parent's %q on the page\n%s", want, out)
		}
	}

	// A pid that is gone is the common case for a number read out of a map, and
	// must not look like a failure.
	gone := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{PID: "1234", Process: &pb.DescribeProcessResponse{Found: false}}})
	if !strings.Contains(gone, "No process <code>1234</code>") {
		t.Errorf("expected the page to say the pid is gone\n%s", gone)
	}
}

// TestUtilsTitleNamesTheLookup keeps a row of lookup tabs navigable: each one is
// named by what was asked, not all "utils".
func TestUtilsTitleNamesTheLookup(t *testing.T) {
	tests := []struct {
		name string
		look *lookupView
		want string
	}{
		{"inode", &lookupView{Inode: "1179921"}, "inode 1179921 - node-a - bpf-explorer"},
		{"pid", &lookupView{PID: "1234"}, "pid 1234 - node-a - bpf-explorer"},
		{"nothing asked", &lookupView{}, "utils - node-a - bpf-explorer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pageTitle("utils", pageData{Node: "node-a", Lookup: tc.look})
			if got != tc.want {
				t.Errorf("pageTitle = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestComma(t *testing.T) {
	for in, want := range map[uint64]string{
		0: "0", 7: "7", 999: "999", 1000: "1,000", 4120013: "4,120,013",
	} {
		if got := comma(in); got != want {
			t.Errorf("comma(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestUtilsWalkOffer checks a /proc miss points at the search that can still
// answer - and that the offer is gone once the walk has been run.
func TestUtilsWalkOffer(t *testing.T) {
	miss := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{Inode: "42", Device: "8:2", Searched: true, Scanned: 300}})
	if !strings.Contains(miss, "walk the filesystem") {
		t.Errorf("a /proc miss should offer the filesystem walk\n%s", miss)
	}
	// The device's colon comes back percent-encoded, as a query value should.
	if !strings.Contains(miss, `?inode=42&dev=8%3a2&root=&pid=&walk=1`) {
		t.Errorf("the offer should carry the lookup over\n%s", miss)
	}

	walked := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{Inode: "42", Searched: true, Scanned: 300, Walk: true,
			Stats: &pb.WalkStats{Ran: true, Root: "/", Device: "8:2", Files: 4120013, Dirs: 91002, Seconds: 42.5}}})
	if strings.Contains(walked, "walk the filesystem</a>") {
		t.Errorf("the walk has already run; the offer should be gone\n%s", walked)
	}
	for _, want := range []string{"4,120,013 files", "91,002 directories", "42.5s", "<code>8:2</code>"} {
		if !strings.Contains(walked, want) {
			t.Errorf("expected walk stats to contain %q\n%s", want, walked)
		}
	}
}

// TestUtilsWalkTimedOut is the distinction that keeps a walk honest: giving up
// early is not the same answer as searching the tree and finding nothing.
func TestUtilsWalkTimedOut(t *testing.T) {
	out := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{Inode: "42", Searched: true, Scanned: 300, Walk: true,
			Stats: &pb.WalkStats{Ran: true, Root: "/", Device: "8:2", Files: 2000000, Seconds: 60.0, TimedOut: true}}})
	if !strings.Contains(out, "Gave up with the tree unfinished") {
		t.Errorf("a walk that ran out of time must say so\n%s", out)
	}
	if !strings.Contains(out, `class="warn"`) {
		t.Errorf("an unfinished walk is a warning, not a quiet note\n%s", out)
	}

	// A walk that could not start at all is a different message again.
	refused := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{Inode: "42", Searched: true, Scanned: 300, Walk: true,
			Stats: &pb.WalkStats{Note: "device 99:1 is not in the mount table"}}})
	if !strings.Contains(refused, "No walk: device 99:1 is not in the mount table") {
		t.Errorf("a refused walk should say why\n%s", refused)
	}
}

// TestUtilsWalkOnlyMatch renders the answer the /proc tiers cannot give: a file
// on disk that nothing holds.
func TestUtilsWalkOnlyMatch(t *testing.T) {
	out := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{Inode: "42", Searched: true, Scanned: 300, Walk: true,
			Matches: []*pb.InodeMatch{{Path: "/srv/data/cold.db", Device: "8:2", Mount: "/", FromWalk: true}},
			Stats:   &pb.WalkStats{Ran: true, Root: "/", Device: "8:2", Files: 12, Dirs: 3, Seconds: 0.1}}})

	for _, want := range []string{"/srv/data/cold.db", "nothing - on disk only"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
}

func renderUtils(t *testing.T, data pageData) string {
	t.Helper()
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.render(rec, "utils", data)
	return rec.Body.String()
}

// TestUtilsPidLookupComesFirst pins the order of the page: a pid is what a map
// dump hands you most often, so its lookup is the one the page opens on.
func TestUtilsPidLookupComesFirst(t *testing.T) {
	out := renderUtils(t, pageData{Node: "node-a", Tab: "utils", Lookup: &lookupView{}})

	pid, inode := strings.Index(out, "pid -&gt; process"), strings.Index(out, "inode -&gt; path")
	if pid < 0 || inode < 0 {
		t.Fatalf("expected both lookups on the page\n%s", out)
	}
	if pid > inode {
		t.Errorf("the pid lookup should come before the inode one\n%s", out)
	}
	// The cursor belongs in the field at the top.
	if !regexp.MustCompile(`<input[^>]*name="pid"[^>]*autofocus`).MatchString(out) {
		t.Errorf("expected the pid field to take the focus\n%s", out)
	}
	if regexp.MustCompile(`<input[^>]*name="inode"[^>]*autofocus`).MatchString(out) {
		t.Errorf("only one field can hold the focus, and it is the first\n%s", out)
	}
}

// TestUtilsParentUnknown covers the parent lookups that answer nothing: the row
// still links onwards, and says which kind of nothing it got.
func TestUtilsParentUnknown(t *testing.T) {
	process := func(ppid uint32) *pb.DescribeProcessResponse {
		return &pb.DescribeProcessResponse{Found: true, Pid: 1234, Comm: "loader", Ppid: ppid}
	}

	// The parent exited between the two reads.
	gone := renderUtils(t, pageData{Node: "node-a", Tab: "utils", Lookup: &lookupView{
		PID: "1234", Process: process(4242),
		Parent: &pb.DescribeProcessResponse{Found: false},
	}})
	if !strings.Contains(gone, "?(4242)") {
		t.Errorf("a parent with no name still links by number\n%s", gone)
	}
	if !strings.Contains(gone, "exited between the two reads") {
		t.Errorf("expected the page to say why the parent has no detail\n%s", gone)
	}

	// The parent was never asked about, because asking failed.
	unasked := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{PID: "1234", Process: process(4242)}})
	if !strings.Contains(unasked, "?(4242)") {
		t.Errorf("the ppid links onwards whether or not it could be described\n%s", unasked)
	}
	if strings.Contains(unasked, "exited between the two reads") {
		t.Errorf("nothing was learned about the parent, so nothing is claimed\n%s", unasked)
	}

	// Pid 0 is the kernel's own ancestor: there is nowhere to go from here.
	kernel := renderUtils(t, pageData{Node: "node-a", Tab: "utils",
		Lookup: &lookupView{PID: "2", Process: process(0)}})
	if strings.Contains(kernel, "pid=0") {
		t.Errorf("a process with no parent should not link to pid 0\n%s", kernel)
	}
}

func TestParentComm(t *testing.T) {
	tests := []struct {
		name string
		look lookupView
		want string
	}{
		{"named", lookupView{Parent: &pb.DescribeProcessResponse{Found: true, Comm: "bash"}}, "bash"},
		{"gone", lookupView{Parent: &pb.DescribeProcessResponse{Found: false}}, "?"},
		{"nameless", lookupView{Parent: &pb.DescribeProcessResponse{Found: true}}, "?"},
		{"never asked", lookupView{}, "?"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.look.ParentComm(); got != tt.want {
				t.Errorf("ParentComm() = %q, want %q", got, tt.want)
			}
		})
	}
}
