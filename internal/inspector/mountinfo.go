package inspector

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// mountEntry is the part of a mountinfo line this package reads: the inode
// lookup names the filesystem a match was found on, the cgroup code asks what
// kind of hierarchy is mounted. The line is parsed once, here.
type mountEntry struct {
	Device string // "major:minor" of the filesystem
	Point  string // where it is mounted, as the reading process sees it
	FSType string // "cgroup2", "ext4", ... empty when the line has no separator
}

// parseMountinfo reads one line of a mountinfo table:
//
//	36 26 0:31 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw
//	           ^dev             ^point                ^fstype
//
// The fields before the "-" are fixed in number, the ones after it are not, and
// between them sit optional fields that may not be there at all - which is why
// the type is found by the separator rather than by counting from either end.
func parseMountinfo(line string) (mountEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return mountEntry{}, false
	}
	e := mountEntry{Device: fields[2], Point: fields[4]}
	// The optional fields start at the seventh, so a "-" before that is part of
	// a path rather than the separator.
	for i := 6; i < len(fields)-1; i++ {
		if fields[i] == "-" {
			e.FSType = fields[i+1]
			break
		}
	}
	return e, true
}

// eachMount calls fn for every mount in one process's table, stopping early when
// fn returns false. A table that cannot be read - the process is gone, or /proc
// is not visible - calls fn not at all and is not an error to the callers here,
// each of which has a next place to look.
func eachMount(procRoot, pid string, fn func(mountEntry) bool) {
	f, err := os.Open(filepath.Join(procRoot, pid, "mountinfo"))
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		e, ok := parseMountinfo(sc.Text())
		if !ok {
			continue
		}
		if !fn(e) {
			return
		}
	}
}

// readMounts maps "major:minor" to a mount point, so an inode match can say
// which filesystem it was found on. Read from pid 1, whose mount table is the
// host's when the agent can see host pids; several mounts may share a device
// (bind mounts), and the first one named wins.
func readMounts(procRoot string) map[string]string {
	mounts := map[string]string{}
	for _, pid := range []string{"1", "self"} {
		eachMount(procRoot, pid, func(e mountEntry) bool {
			if _, ok := mounts[e.Device]; !ok {
				mounts[e.Device] = e.Point
			}
			return true
		})
		if len(mounts) > 0 {
			return mounts
		}
	}
	return mounts
}
