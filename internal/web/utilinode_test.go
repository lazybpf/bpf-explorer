package web

import (
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

// TestUtilInodePageEmpty checks the page offers its lookup before one has been
// asked for, and claims nothing about results it has not searched for.
func TestUtilInodePageEmpty(t *testing.T) {
	out := renderUtilInode(t, &inodeLookup{})

	for _, want := range []string{
		`name="inode"`,
		`name="dev"`,
		`name="root"`,
		`action="/nodes/node-a/utils/inode"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
	// The inode is what this page asks for, so the cursor starts there.
	if !regexp.MustCompile(`<input[^>]*name="inode"[^>]*autofocus`).MatchString(out) {
		t.Errorf("expected the inode field to take the focus\n%s", out)
	}
	if strings.Contains(out, "Nothing holds inode") {
		t.Error("page reported a miss without a lookup having run")
	}
}

// TestUtilInodeMatches renders the answer: the path, where it lives, and every
// holder - grouped under one path rather than repeated per process.
func TestUtilInodeMatches(t *testing.T) {
	out := renderUtilInode(t, &inodeLookup{
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
	})

	for _, want := range []string{
		"/usr/sbin/nginx",
		"253:1",
		"nginx(2000)",
		"mapped",
		"logger(2001)",
		"fd 7",
		// A holder is a pid, so it links across to the utility that describes
		// one - carrying nothing else, now that each lookup has its own page.
		`href="/nodes/node-a/utils/pid?pid=2000"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
}

// TestUtilInodeManyHoldersAreCapped keeps the path readable: libc is mapped by
// nearly every process on a node, and a cell listing all of them buries the
// answer it belongs to.
func TestUtilInodeManyHoldersAreCapped(t *testing.T) {
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

	out := renderUtilInode(t, &inodeLookup{Inode: "42", Searched: true, Scanned: 300,
		Matches: []*pb.InodeMatch{{Path: "/lib/libc.so.6", Device: "8:2", Holders: all}}})
	if !strings.Contains(out, "and 91 more, 99 in all") {
		t.Errorf("expected the held-back holders to be counted\n%s", out)
	}
	if strings.Contains(out, "proc(99)") {
		t.Error("holder 99 is past the cap and should not be rendered")
	}
}

// TestUtilInodeMissDistinguishesNothingSearched is the honesty the page turns
// on: "nothing holds it" and "nothing was searched" are different answers, and
// only the first one is about the inode.
func TestUtilInodeMissDistinguishesNothingSearched(t *testing.T) {
	searched := renderUtilInode(t, &inodeLookup{Inode: "42", Searched: true, Scanned: 312})
	if !strings.Contains(searched, "Nothing holds inode") {
		t.Errorf("a real miss should say nothing holds it\n%s", searched)
	}
	if !strings.Contains(searched, "312 processes") {
		t.Errorf("a miss should say how much was searched\n%s", searched)
	}

	blind := renderUtilInode(t, &inodeLookup{Inode: "42", Searched: true, Scanned: 0})
	if !strings.Contains(blind, "No processes were searched") {
		t.Errorf("an unsearchable /proc must not read as a miss\n%s", blind)
	}
	if strings.Contains(blind, "Nothing holds inode") {
		t.Errorf("nothing was searched, so nothing can be concluded\n%s", blind)
	}
}

// TestUtilInodeInAnotherNamespace covers the container case: the holder's path
// is not the agent's, so the reachable form has to be shown too.
func TestUtilInodeInAnotherNamespace(t *testing.T) {
	out := renderUtilInode(t, &inodeLookup{
		Inode: "42", Searched: true, Scanned: 9,
		Matches: []*pb.InodeMatch{{
			Path:     "/app/config.yaml",
			Device:   "0:52",
			Deleted:  true,
			HostPath: "/proc/8123/root/app/config.yaml",
			Holders:  []*pb.InodeHolder{{Pid: 8123, Comm: "app", Source: "fd", Fd: "3"}},
		}},
	})

	for _, want := range []string{"/proc/8123/root/app/config.yaml", "another mount namespace", "deleted"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
}

// TestUtilInodeWalkOffer checks a /proc miss points at the search that can still
// answer - and that the offer is gone once the walk has been run.
func TestUtilInodeWalkOffer(t *testing.T) {
	miss := renderUtilInode(t, &inodeLookup{Inode: "42", Device: "8:2", Searched: true, Scanned: 300})
	if !strings.Contains(miss, "walk the filesystem") {
		t.Errorf("a /proc miss should offer the filesystem walk\n%s", miss)
	}
	// The device's colon comes back percent-encoded, as a query value should.
	if !strings.Contains(miss, `?inode=42&dev=8%3a2&root=&walk=1`) {
		t.Errorf("the offer should carry the lookup over\n%s", miss)
	}

	walked := renderUtilInode(t, &inodeLookup{Inode: "42", Searched: true, Scanned: 300, Walk: true,
		Stats: &pb.WalkStats{Ran: true, Root: "/", Device: "8:2", Files: 4120013, Dirs: 91002, Seconds: 42.5}})
	if strings.Contains(walked, "walk the filesystem</a>") {
		t.Errorf("the walk has already run; the offer should be gone\n%s", walked)
	}
	for _, want := range []string{"4,120,013 files", "91,002 directories", "42.5s", "<code>8:2</code>"} {
		if !strings.Contains(walked, want) {
			t.Errorf("expected walk stats to contain %q\n%s", want, walked)
		}
	}
}

// TestUtilInodeWalkTimedOut is the distinction that keeps a walk honest: giving
// up early is not the same answer as searching the tree and finding nothing.
func TestUtilInodeWalkTimedOut(t *testing.T) {
	out := renderUtilInode(t, &inodeLookup{Inode: "42", Searched: true, Scanned: 300, Walk: true,
		Stats: &pb.WalkStats{Ran: true, Root: "/", Device: "8:2", Files: 2000000, Seconds: 60.0, TimedOut: true}})
	if !strings.Contains(out, "Gave up with the tree unfinished") {
		t.Errorf("a walk that ran out of time must say so\n%s", out)
	}
	if !strings.Contains(out, `class="warn"`) {
		t.Errorf("an unfinished walk is a warning, not a quiet note\n%s", out)
	}

	// A walk that could not start at all is a different message again.
	refused := renderUtilInode(t, &inodeLookup{Inode: "42", Searched: true, Scanned: 300, Walk: true,
		Stats: &pb.WalkStats{Note: "device 99:1 is not in the mount table"}})
	if !strings.Contains(refused, "No walk: device 99:1 is not in the mount table") {
		t.Errorf("a refused walk should say why\n%s", refused)
	}
}

// TestUtilInodeWalkOnlyMatch renders the answer the /proc tiers cannot give: a
// file on disk that nothing holds.
func TestUtilInodeWalkOnlyMatch(t *testing.T) {
	out := renderUtilInode(t, &inodeLookup{Inode: "42", Searched: true, Scanned: 300, Walk: true,
		Matches: []*pb.InodeMatch{{Path: "/srv/data/cold.db", Device: "8:2", Mount: "/", FromWalk: true}},
		Stats:   &pb.WalkStats{Ran: true, Root: "/", Device: "8:2", Files: 12, Dirs: 3, Seconds: 0.1}})

	for _, want := range []string{"/srv/data/cold.db", "nothing - on disk only"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
}

// TestUtilInodeTitle keeps a row of lookup tabs navigable: each one is named by
// what was asked of it, and by the utility itself before anything was.
func TestUtilInodeTitle(t *testing.T) {
	tests := []struct {
		name string
		look *inodeLookup
		want string
	}{
		{"asked", &inodeLookup{Inode: "1179921"}, "inode 1179921 - node-a - bpf-explorer"},
		{"nothing asked", &inodeLookup{}, "inode lookup - node-a - bpf-explorer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pageTitle("utilinode", pageData{Node: "node-a", InodeLookup: tc.look})
			if got != tc.want {
				t.Errorf("pageTitle = %q, want %q", got, tc.want)
			}
		})
	}
}

func renderUtilInode(t *testing.T, look *inodeLookup) string {
	t.Helper()
	return renderUtil(t, "utilinode", pageData{Node: "node-a", Tab: "utils", Util: "inode", InodeLookup: look})
}
