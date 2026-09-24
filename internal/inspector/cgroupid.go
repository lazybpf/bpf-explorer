package inspector

import (
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
)

// cgroupWalkLimit caps how many directories the hierarchy walk visits. A node's
// unified tree is a few hundred directories, a busy one a few thousand; the cap
// is there so a tree that is somehow enormous costs a bounded amount rather than
// holding up the links page.
const cgroupWalkLimit = 50000

// cgroupV2Root returns the cgroup2 mount point, prefixed so the agent can reach
// it. Only the unified hierarchy is looked for: a BPF cgroup link can only be
// made against cgroup v2, so a v1 controller mount would name nothing a link
// points at.
//
// Pid 1's mount table is read first, as the rest of this package does and for
// the same reason: with hostPID that is the node's init, and its table names the
// node's own tree rather than whatever subtree the agent's runtime handed its
// container. Paths in that table are in pid 1's mount namespace, which is why
// they are reached through its root - the agent's own /sys/fs/cgroup is a
// different mount, showing only the container's own cgroup.
func cgroupV2Root(procRoot string) string {
	for _, pid := range []string{"1", "self"} {
		var point string
		eachMount(procRoot, pid, func(e mountEntry) bool {
			if e.FSType == "cgroup2" {
				point = e.Point
				return false
			}
			return true
		})
		switch {
		case point == "":
			continue
		case pid == "1":
			return filepath.Join(hostPrefix(procRoot), point)
		default:
			// Read from the agent's own table, so it is already a path the
			// agent can open, and prefixing it would break it.
			return point
		}
	}
	return ""
}

// walkCgroupPaths maps every cgroup under root to the path that names it,
// relative to the hierarchy root ("/" for the root cgroup itself) - which is how
// the node spells a cgroup path everywhere else, and what /proc/<pid>/cgroup
// holds.
//
// The key is the directory's inode number, which for cgroup v2 is the cgroup id
// the kernel reports on a link: kernfs hands out a 64-bit node id and, where
// ino_t is 64 bits wide, the inode is that id whole.
//
// Best-effort throughout: a subtree that cannot be read is skipped rather than
// failing the walk, since a partial index still names most links.
func walkCgroupPaths(root string) map[uint64]string {
	index := map[uint64]string{}
	var dev uint64
	visited := 0
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil //nolint:nilerr // an unreadable corner is not a failed walk
		}
		if visited++; visited > cgroupWalkLimit {
			return fs.SkipAll
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		// Whatever is mounted inside the hierarchy is not part of it, and its
		// inode numbers are another filesystem's.
		if dev == 0 {
			dev = uint64(st.Dev)
		} else if uint64(st.Dev) != dev {
			return fs.SkipDir
		}
		rel := strings.TrimPrefix(path, root)
		if rel == "" {
			rel = "/"
		}
		index[uint64(st.Ino)] = rel
		return nil
	})
	return index
}
