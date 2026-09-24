package inspector

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestCgroupV2Root checks which mount the hierarchy walk is pointed at: the
// unified one rather than a v1 controller's, pid 1's table before the agent's,
// and nothing at all on a node with no cgroup2 mounted.
func TestCgroupV2Root(t *testing.T) {
	const (
		v2  = "36 26 0:31 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw,nsdelegate\n"
		v1  = "31 24 0:26 / /sys/fs/cgroup/memory rw,nosuid shared:10 - cgroup cgroup rw,memory\n"
		alt = "30 24 0:25 / /sys/fs/cgroup/unified rw,nosuid shared:9 - cgroup2 cgroup2 rw\n"
	)
	tests := []struct {
		name      string
		one, self string
		want      string
	}{
		{"unified from pid 1", v2, "", "/sys/fs/cgroup"},
		{"v1 controllers hold no links", v1, "", ""},
		{"hybrid: the cgroup2 mount, not the controllers", v1 + alt, "", "/sys/fs/cgroup/unified"},
		{"pid 1 first", v2, alt, "/sys/fs/cgroup"},
		{"the agent's own table when pid 1 has none", "", alt, "/sys/fs/cgroup/unified"},
		{"no cgroup2 anywhere", "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			procRoot := t.TempDir()
			writeMountinfo(t, procRoot, "1", tc.one)
			writeMountinfo(t, procRoot, "self", tc.self)

			// No ns links in the fake /proc, so hostPrefix adds nothing: the
			// point is the mount that is chosen, not how it is reached.
			if got := cgroupV2Root(procRoot); got != tc.want {
				t.Errorf("cgroupV2Root = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWalkCgroupPaths checks the index a cgroup link's id is looked up in: every
// directory keyed by its own inode, named relative to the hierarchy root, with
// the root itself as "/" - the way /proc/<pid>/cgroup spells a cgroup path.
func TestWalkCgroupPaths(t *testing.T) {
	root := t.TempDir()
	dirs := []string{
		"kubepods.slice",
		"kubepods.slice/kubepods-besteffort.slice",
		"kubepods.slice/kubepods-besteffort.slice/pod83b.slice",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Files sit alongside the directories in a real hierarchy (cgroup.procs and
	// the rest) and are not cgroups; none of them may end up in the index.
	if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	index := walkCgroupPaths(root)
	if len(index) != len(dirs)+1 {
		t.Fatalf("indexed %d cgroups, want %d (the root and its %d children)", len(index), len(dirs)+1, len(dirs))
	}
	if got := index[inodeOf(t, root)]; got != "/" {
		t.Errorf("the root cgroup is %q, want %q", got, "/")
	}
	for _, d := range dirs {
		want := "/" + d
		if got := index[inodeOf(t, filepath.Join(root, d))]; got != want {
			t.Errorf("cgroup %s is %q, want %q", d, got, want)
		}
	}
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no stat for %s", path)
	}
	return uint64(st.Ino)
}
