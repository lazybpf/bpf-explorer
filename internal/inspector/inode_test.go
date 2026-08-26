package inspector

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// realFile creates a file and returns its inode and "major:minor" device, so a
// test can look for something the running kernel actually agrees exists - the fd
// tier stats what an fd symlink points at, and a made-up inode would never
// match.
func realFile(t *testing.T, path, contents string) (uint64, string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no syscall.Stat_t for %s", path)
	}
	return st.Ino, deviceString(uint64(st.Dev))
}

// writeProcFDs lays out a fake /proc/<pid> whose fd entries point at real files.
func writeProcFDs(t *testing.T, root, pid, comm string, fds map[string]string) {
	t.Helper()
	procDir := filepath.Join(root, pid)
	if err := os.MkdirAll(filepath.Join(procDir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for fd, target := range fds {
		if err := os.Symlink(target, filepath.Join(procDir, "fd", fd)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestResolveInodeFromOpenFD covers the tier that answers most lookups: a
// process holding the file open, named with the fd it holds it on.
func TestResolveInodeFromOpenFD(t *testing.T) {
	root := t.TempDir()
	files := t.TempDir()

	target := filepath.Join(files, "wanted")
	inode, device := realFile(t, target, "hello")
	other := filepath.Join(files, "other")
	realFile(t, other, "unrelated")

	writeProcFDs(t, root, "1000", "reader", map[string]string{"3": target, "4": other})
	writeProcFDs(t, root, "1001", "writer", map[string]string{"7": target})
	writeProcFDs(t, root, "1002", "idle", map[string]string{"3": other})

	matches, scanned := resolveInode(root, inode, "")
	if scanned != 3 {
		t.Errorf("scanned %d processes, want 3", scanned)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want the one path\n%+v", len(matches), matches)
	}

	m := matches[0]
	if m.Path != target {
		t.Errorf("path %q, want %q", m.Path, target)
	}
	if m.Device != device {
		t.Errorf("device %q, want %q", m.Device, device)
	}
	if m.Deleted {
		t.Error("file is not deleted")
	}
	// Both holders, grouped under the one path rather than reported as two
	// separate answers.
	if len(m.Holders) != 2 {
		t.Fatalf("got %d holders, want 2\n%+v", len(m.Holders), m.Holders)
	}
	want := map[uint32]InodeHolder{
		1000: {PID: 1000, Comm: "reader", Source: sourceFD, FD: "3"},
		1001: {PID: 1001, Comm: "writer", Source: sourceFD, FD: "7"},
	}
	for _, h := range m.Holders {
		if h != want[h.PID] {
			t.Errorf("holder %+v, want %+v", h, want[h.PID])
		}
	}
}

// TestResolveInodeFromMaps covers the mapping tier, which is how an executable
// or shared library gets found: no process has it on an fd, but every process
// running it has it mapped.
func TestResolveInodeFromMaps(t *testing.T) {
	root := t.TempDir()

	procDir := filepath.Join(root, "2000")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte("nginx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	maps := "" +
		"55a4f2e00000-55a4f2e21000 r-xp 00000000 fd:01 1179921    /usr/sbin/nginx\n" +
		"55a4f2e21000-55a4f2e30000 r--p 00021000 fd:01 1179921    /usr/sbin/nginx\n" +
		"7f1c8b400000-7f1c8b600000 r-xp 00000000 fd:01 262401     /usr/lib/libc.so.6\n" +
		"7ffd2b1f9000-7ffd2b21a000 rw-p 00000000 00:00 0          [stack]\n"
	if err := os.WriteFile(filepath.Join(procDir, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}

	matches, scanned := resolveInode(root, 1179921, "")
	if scanned != 1 {
		t.Errorf("scanned %d processes, want 1", scanned)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1\n%+v", len(matches), matches)
	}
	// Mapped as two segments, reported once.
	m := matches[0]
	if m.Path != "/usr/sbin/nginx" || m.Device != "253:1" {
		t.Errorf("got %q on %q, want /usr/sbin/nginx on 253:1", m.Path, m.Device)
	}
	if len(m.Holders) != 1 || m.Holders[0] != (InodeHolder{PID: 2000, Comm: "nginx", Source: sourceMap}) {
		t.Errorf("holders %+v, want one map holder 2000/nginx", m.Holders)
	}

	// The anonymous [stack] line carries inode 0, which must never match: it
	// would otherwise answer every lookup for 0 with every process on the node.
	if got, _ := resolveInode(root, 0, ""); got != nil {
		t.Errorf("inode 0 matched %+v, want no answer", got)
	}
}

// TestResolveInodeDeviceFilter checks the filter that makes an answer
// trustworthy: the same inode number on two filesystems is two different files.
func TestResolveInodeDeviceFilter(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "3000")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	maps := "" +
		"55a4f2e00000-55a4f2e21000 r-xp 00000000 fd:01 4242   /on/root\n" +
		"7f1c8b400000-7f1c8b600000 r-xp 00000000 08:02 4242   /on/data\n"
	if err := os.WriteFile(filepath.Join(procDir, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}

	if all, _ := resolveInode(root, 4242, ""); len(all) != 2 {
		t.Fatalf("unfiltered lookup got %d matches, want both filesystems\n%+v", len(all), all)
	}
	one, _ := resolveInode(root, 4242, "8:2")
	if len(one) != 1 || one[0].Path != "/on/data" {
		t.Fatalf("filtered lookup got %+v, want only /on/data", one)
	}
}

// TestResolveInodeUnreadableProc is the case the UI must not mistake for "not
// found": with no visible /proc there is nothing to search, so the answer is
// that nothing was searched.
func TestResolveInodeUnreadableProc(t *testing.T) {
	matches, scanned := resolveInode(filepath.Join(t.TempDir(), "missing"), 42, "")
	if matches != nil || scanned != 0 {
		t.Errorf("got %+v scanned=%d, want no matches and nothing scanned", matches, scanned)
	}
}

// TestResolveInodeDeleted checks an unlinked file still resolves: the holder is
// exactly what keeps it alive, and "(deleted)" is the answer, not noise.
func TestResolveInodeDeleted(t *testing.T) {
	root := t.TempDir()
	files := t.TempDir()

	// /proc renders an unlinked file's fd as "<path> (deleted)". Faking that
	// takes a link target carrying the suffix and a real file behind it, since
	// the fd tier stats what the link points at.
	target := filepath.Join(files, "gone")
	inode, _ := realFile(t, target+" (deleted)", "x")
	writeProcFDs(t, root, "4000", "holder", map[string]string{"5": target + " (deleted)"})

	matches, _ := resolveInode(root, inode, "")
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1\n%+v", len(matches), matches)
	}
	if !matches[0].Deleted || matches[0].Path != target {
		t.Errorf("got path %q deleted=%v, want %q deleted", matches[0].Path, matches[0].Deleted, target)
	}
}

// TestWalkFindsUnheldFile is the case the /proc tiers cannot answer at all: a
// file on disk that no process has open. This is why the walk exists.
func TestWalkFindsUnheldFile(t *testing.T) {
	root := t.TempDir()
	tree := filepath.Join(root, "srv", "data")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tree, "wanted.db")
	inode, device := realFile(t, target, "payload")
	realFile(t, filepath.Join(tree, "other.db"), "decoy")

	plan, note := walkTarget(t.TempDir(), root, "")
	if note != "" {
		t.Fatalf("walkTarget: %s", note)
	}
	if plan.device != device {
		t.Fatalf("plan device %q, want %q", plan.device, device)
	}

	matches, stats := walkForInode(plan, inode, time.Minute)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1\n%+v", len(matches), matches)
	}
	if matches[0].Path != target || !matches[0].FromWalk {
		t.Errorf("got %q fromWalk=%v, want %q found by the walk",
			matches[0].Path, matches[0].FromWalk, target)
	}
	if !stats.Ran || stats.TimedOut {
		t.Errorf("stats = %+v, want a completed walk", stats)
	}
	// The walk stops as soon as it has every link the inode claims, so a
	// single-link file must not have cost a full sweep of the tree.
	if stats.Files == 0 {
		t.Error("stats should count the entries it stat'ed")
	}
}

// TestWalkFindsEveryHardLink is the other thing only a walk can do: one inode,
// several names. The /proc tiers see only the name a holder opened.
func TestWalkFindsEveryHardLink(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "a-name")
	inode, _ := realFile(t, first, "shared")
	second := filepath.Join(root, "z-other-name")
	if err := os.Link(first, second); err != nil {
		t.Fatal(err)
	}

	plan, note := walkTarget(t.TempDir(), root, "")
	if note != "" {
		t.Fatalf("walkTarget: %s", note)
	}
	matches, stats := walkForInode(plan, inode, time.Minute)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want both links\n%+v", len(matches), matches)
	}
	got := []string{matches[0].Path, matches[1].Path}
	sort.Strings(got)
	if got[0] != first || got[1] != second {
		t.Errorf("got %v, want %v", got, []string{first, second})
	}
	if stats.TimedOut {
		t.Error("walk should have finished: both links were found")
	}
}

// TestWalkFindsDirectory covers cgroup ids, which are the inode numbers of
// cgroupfs directories - so a directory has to be a valid answer.
func TestWalkFindsDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "kubepods.slice")
	if err := os.MkdirAll(filepath.Join(target, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	inode := fi.Sys().(*syscall.Stat_t).Ino

	plan, note := walkTarget(t.TempDir(), root, "")
	if note != "" {
		t.Fatalf("walkTarget: %s", note)
	}
	matches, _ := walkForInode(plan, inode, time.Minute)
	if len(matches) != 1 || matches[0].Path != target {
		t.Fatalf("got %+v, want the directory %q", matches, target)
	}
}

// TestWalkBudgetExpires checks a walk that runs out of time says so and returns
// what it has, rather than failing or silently looking like a miss.
func TestWalkBudgetExpires(t *testing.T) {
	root := t.TempDir()
	// Enough entries that the 512-entry clock check is reached.
	for i := 0; i < 1200; i++ {
		realFile(t, filepath.Join(root, "f"+strconv.Itoa(i)), "x")
	}
	plan, note := walkTarget(t.TempDir(), root, "")
	if note != "" {
		t.Fatalf("walkTarget: %s", note)
	}

	// A budget already spent: the first clock check gives up.
	matches, stats := walkForInode(plan, 1, -time.Second)
	if !stats.TimedOut {
		t.Errorf("stats = %+v, want timed out", stats)
	}
	if matches != nil {
		t.Errorf("got %+v, want nothing found", matches)
	}
}

// TestWalkTargetFromDevice checks a device narrows where the walk starts: its
// mount point, since the same inode on another filesystem is a different file.
func TestWalkTargetFromDevice(t *testing.T) {
	procRoot := t.TempDir()
	tree := t.TempDir()
	realDev, err := deviceOf(tree)
	if err != nil {
		t.Fatal(err)
	}

	// A mount table naming the same directory twice: once under the device it is
	// really on, once under a device it is not.
	mountinfo := fmt.Sprintf("36 35 %s / %s rw,relatime - ext4 /dev/sda2 rw\n", realDev, tree) +
		fmt.Sprintf("37 35 99:1 / %s rw,relatime - ext4 /dev/sdb1 rw\n", tree)
	if err := os.MkdirAll(filepath.Join(procRoot, "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "1", "mountinfo"), []byte(mountinfo), 0o644); err != nil {
		t.Fatal(err)
	}

	// A device resolves to its mount point, which becomes the walk root.
	plan, note := walkTarget(procRoot, "", realDev)
	if note != "" {
		t.Fatalf("walkTarget(%s): %s", realDev, note)
	}
	if plan.hostRoot != tree || plan.device != realDev {
		t.Errorf("plan = %+v, want root %q on %q", plan, tree, realDev)
	}

	// A mount that is not actually on the device asked for must be refused, not
	// walked: an inode found there would belong to a different file.
	if _, note := walkTarget(procRoot, "", "99:1"); !strings.Contains(note, "not 99:1") {
		t.Errorf("note = %q, want it to refuse the mismatched device", note)
	}
	// A device with no mount at all cannot be walked, and says so.
	if _, note := walkTarget(procRoot, "", "99:99"); !strings.Contains(note, "not in the mount table") {
		t.Errorf("note = %q, want it to say the device has no mount", note)
	}
}

// TestResolveInodeQueryMergesWalk checks the two searches come back as one
// answer: the held path keeps its holders, and a link only the walk found is
// added rather than replacing it.
func TestResolveInodeQueryMergesWalk(t *testing.T) {
	procRoot := t.TempDir()
	files := t.TempDir()

	held := filepath.Join(files, "held")
	inode, _ := realFile(t, held, "shared")
	link := filepath.Join(files, "zz-link")
	if err := os.Link(held, link); err != nil {
		t.Fatal(err)
	}
	writeProcFDs(t, procRoot, "1000", "holder", map[string]string{"3": held})

	res := resolveInodeQuery(procRoot, InodeQuery{
		Inode: inode, Walk: true, WalkRoot: files, WalkBudget: time.Minute,
	})
	if len(res.Matches) != 2 {
		t.Fatalf("got %d matches, want the held path and the extra link\n%+v", len(res.Matches), res.Matches)
	}
	byPath := map[string]InodeMatch{}
	for _, m := range res.Matches {
		byPath[m.Path] = m
	}
	if m := byPath[held]; len(m.Holders) != 1 || m.FromWalk {
		t.Errorf("held path = %+v, want its holder kept and not marked as walk-only", m)
	}
	if m := byPath[link]; len(m.Holders) != 0 || !m.FromWalk {
		t.Errorf("extra link = %+v, want no holders and marked as walk-only", m)
	}
	if !res.Walk.Ran {
		t.Error("walk stats should say it ran")
	}
}

// TestResolveInodeQueryWalkNotAsked keeps the walk opt-in: it costs minutes on a
// real tree, so it must never run as an unrequested fallback.
func TestResolveInodeQueryWalkNotAsked(t *testing.T) {
	res := resolveInodeQuery(t.TempDir(), InodeQuery{Inode: 42})
	if res.Walk.Ran {
		t.Error("walk ran without being asked for")
	}
}

func TestParseMapsLine(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		device string
		inode  uint64
		path   string
		ok     bool
	}{
		{
			name: "file backed", device: "253:1", inode: 1179921, path: "/usr/sbin/nginx", ok: true,
			line: "55a4f2e00000-55a4f2e21000 r-xp 00000000 fd:01 1179921    /usr/sbin/nginx",
		},
		{
			// A pathname may contain spaces, so it is the rest of the line and
			// not a sixth whitespace-separated field.
			name: "path with spaces", device: "8:2", inode: 77, path: "/srv/my data/file.db", ok: true,
			line: "7f00-7f01 r--p 00000000 08:02 77 /srv/my data/file.db",
		},
		{
			name: "anonymous", device: "0:0", inode: 0, path: "[stack]", ok: true,
			line: "7ffd2b1f9000-7ffd2b21a000 rw-p 00000000 00:00 0          [stack]",
		},
		{
			name: "no path", device: "0:0", inode: 0, path: "", ok: true,
			line: "7f00-7f01 rw-p 00000000 00:00 0",
		},
		{name: "truncated", line: "7f00-7f01 rw-p 00000000"},
		{name: "empty", line: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			device, inode, path, ok := parseMapsLine(tc.line)
			got := fmt.Sprintf("%q %d %q %v", device, inode, path, ok)
			want := fmt.Sprintf("%q %d %q %v", tc.device, tc.inode, tc.path, tc.ok)
			if got != want {
				t.Errorf("parseMapsLine(%q) = %s, want %s", tc.line, got, want)
			}
		})
	}
}

func TestDescribeProcess(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "1234")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := "Name:\ttrace_loader\nState:\tS (sleeping)\nTgid:\t1234\nPid:\t1234\nPPid:\t1\n" +
		"Uid:\t1000\t1000\t1000\t1000\n"
	write := func(name, contents string) {
		if err := os.WriteFile(filepath.Join(procDir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("status", status)
	write("cmdline", "./loader\x00--verbose\x00")
	write("cgroup", "0::/kubepods.slice/kubepods-besteffort.slice/pod0ddf.slice\n")

	got := describeProcess(root, 1234)
	want := ProcessDetail{
		Found: true, PID: 1234, Comm: "trace_loader", State: "S (sleeping)", PPID: 1,
		UID: "1000", Cmdline: "./loader --verbose",
		Cgroup: "/kubepods.slice/kubepods-besteffort.slice/pod0ddf.slice",
	}
	if got != want {
		t.Errorf("describeProcess =\n%+v\nwant\n%+v", got, want)
	}

	// A pid that is gone reports not-found rather than an empty-looking process.
	if gone := describeProcess(root, 9999); gone.Found {
		t.Errorf("missing pid reported as found: %+v", gone)
	}
}

// TestReadCgroupV1Fallback checks a node with no unified hierarchy still yields
// a path, taken from the first v1 entry.
func TestReadCgroupV1Fallback(t *testing.T) {
	dir := t.TempDir()
	v1 := "11:devices:/system.slice/docker.service\n10:memory:/system.slice/docker.service\n"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(v1), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readCgroup(dir); got != "/system.slice/docker.service" {
		t.Errorf("readCgroup = %q, want the first v1 path", got)
	}
}
