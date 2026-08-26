package inspector

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// InodeHolder is one process holding a path open or mapped.
type InodeHolder struct {
	PID  uint32
	Comm string
	// Source is how the process was found to hold it: "fd" for an open file
	// descriptor (FD names it) or "map" for a file-backed memory mapping.
	Source string
	FD     string
}

// InodeMatch is one path found for an inode, with every process holding it.
type InodeMatch struct {
	Path     string
	Device   string
	Mount    string
	Deleted  bool
	HostPath string
	Holders  []InodeHolder
	// FromWalk marks a path only the filesystem walk found: a file on disk that
	// no process holds, or a hard link the holders do not use.
	FromWalk bool
}

const (
	sourceFD  = "fd"
	sourceMap = "map"
)

// InodeQuery is one inode lookup. Walk asks for the filesystem search as well,
// which is the only way to find a file no process holds.
type InodeQuery struct {
	Inode  uint64
	Device string

	Walk       bool
	WalkRoot   string
	WalkBudget time.Duration
}

// InodeResult is what a lookup found, and what it was able to look at. Scanned
// is how many processes the /proc search covered: with none, an empty Matches
// means /proc was not visible, not that the inode is unheld.
type InodeResult struct {
	Matches []InodeMatch
	Scanned uint32
	Walk    WalkStats
}

// WalkStats records what the filesystem walk did, so "found nothing" can be told
// apart from "ran out of time", and so the cost of the answer is visible.
type WalkStats struct {
	Ran      bool
	Root     string
	Device   string
	Dirs     uint64
	Files    uint64
	TimedOut bool
	Seconds  float64
	Note     string
}

// defaultWalkBudget bounds the filesystem search. A root filesystem with a few
// million files takes minutes to stat, and an answer that arrives with "gave up
// after a minute, here is where I got to" is more useful than one that never
// arrives - the reader can then narrow the root and ask again.
const defaultWalkBudget = time.Minute

// ResolveInode looks an inode up in the node's open file descriptors and memory
// mappings, and - when asked - by walking the filesystem.
//
// There is no kernel call for inode -> path. The /proc tiers therefore answer
// only for a file some process holds at this instant; the walk is what answers
// for a file on disk that nothing has open.
func (i *Inspector) ResolveInode(q InodeQuery) InodeResult {
	return resolveInodeQuery("/proc", q)
}

// resolveInodeQuery runs the /proc search and, if asked, the walk, merging both
// into one set of paths. A file that is both held and on disk is one answer; a
// hard link the holders do not use is another, which only the walk can find.
func resolveInodeQuery(procRoot string, q InodeQuery) InodeResult {
	matches, scanned := resolveInode(procRoot, q.Inode, q.Device)
	result := InodeResult{Matches: matches, Scanned: scanned}
	if !q.Walk || q.Inode == 0 {
		return result
	}

	plan, note := walkTarget(procRoot, q.WalkRoot, q.Device)
	if note != "" {
		result.Walk = WalkStats{Root: q.WalkRoot, Note: note}
		return result
	}
	budget := q.WalkBudget
	if budget <= 0 {
		budget = defaultWalkBudget
	}

	found, stats := walkForInode(plan, q.Inode, budget)
	result.Walk = stats
	result.Matches = mergeMatches(result.Matches, found, procRoot)
	return result
}

// DescribeProcess reports what /proc knows about one pid. Found is false when
// the process is gone or /proc is not visible.
func (i *Inspector) DescribeProcess(pid uint32) ProcessDetail {
	return describeProcess("/proc", pid)
}

// resolveInode walks procRoot, gathering every path that carries inode. Like the
// BPF holder scan it is best-effort: a process that exits mid-walk, or an fd
// that closes under it, is skipped rather than failing the lookup.
func resolveInode(procRoot string, inode uint64, device string) ([]InodeMatch, uint32) {
	// Inode 0 is /proc's placeholder for "no file behind this mapping", so it
	// would match every anonymous region on the node and mean nothing.
	if inode == 0 {
		return nil, 0
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, 0
	}

	mounts := readMounts(procRoot)
	selfNS := mountNS(procRoot, "self")

	// Grouped by device and path: one shared library is mapped by every process
	// that links it, and that is one answer with many holders, not many answers.
	byPath := map[string]*InodeMatch{}
	var order []string
	var scanned uint32

	for _, e := range entries {
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // not a /proc/<pid> directory
		}
		pid := uint32(pid64)
		scanned++

		procDir := filepath.Join(procRoot, e.Name())
		hits := append(fdHits(procDir, inode, device), mapsHits(procDir, inode, device)...)
		if len(hits) == 0 {
			continue
		}

		comm := readComm(procDir)
		for _, hit := range hits {
			key := hit.device + "\x00" + hit.path
			m, ok := byPath[key]
			if !ok {
				m = &InodeMatch{
					Path:    hit.path,
					Device:  hit.device,
					Mount:   mounts[hit.device],
					Deleted: hit.deleted,
					// Only the first holder decides this: the path is the same
					// file either way, and one prefix is enough to reach it.
					HostPath: hostPath(procRoot, pid, hit.path, selfNS),
				}
				byPath[key] = m
				order = append(order, key)
			}
			hit.holder.Comm = comm
			m.Holders = append(m.Holders, hit.holder)
		}
	}

	matches := make([]InodeMatch, 0, len(order))
	for _, key := range order {
		matches = append(matches, *byPath[key])
	}
	sortMatches(matches)
	return matches, scanned
}

// sortMatches puts the answer in a stable order. /proc lists pids as strings, so
// the scan arrives in the order 1, 10, 100, 1000, 11 - sorting means the same
// lookup reads the same way twice, and a holder list trimmed for display starts
// from the oldest process rather than an arbitrary one.
func sortMatches(matches []InodeMatch) {
	sort.Slice(matches, func(a, b int) bool {
		if matches[a].Path != matches[b].Path {
			return matches[a].Path < matches[b].Path
		}
		return matches[a].Device < matches[b].Device
	})
	for i := range matches {
		h := matches[i].Holders
		sort.Slice(h, func(a, b int) bool {
			if h[a].PID != h[b].PID {
				return h[a].PID < h[b].PID
			}
			return h[a].FD < h[b].FD
		})
	}
}

// walkPlan is where the filesystem search will run: the path the agent opens,
// the same place named as the host sees it, and the one filesystem to stay on.
type walkPlan struct {
	agentRoot string
	hostRoot  string
	prefix    string // agent-only prefix, stripped off what the walk reports
	device    string
}

// walkTarget decides where to walk. An explicit root wins; otherwise a device
// narrows the start to that device's mount point, and with neither the search
// starts at the host's root.
func walkTarget(procRoot, hostRoot, device string) (walkPlan, string) {
	prefix := hostPrefix(procRoot)
	if hostRoot == "" && device != "" {
		mount, ok := readMounts(procRoot)[device]
		if !ok {
			return walkPlan{}, fmt.Sprintf("device %s is not in the mount table, so there is no filesystem to walk", device)
		}
		hostRoot = mount
	}
	if hostRoot == "" {
		hostRoot = "/"
	}

	plan := walkPlan{
		agentRoot: filepath.Join(prefix, hostRoot),
		hostRoot:  hostRoot,
		prefix:    prefix,
	}
	dev, err := deviceOf(plan.agentRoot)
	if err != nil {
		return walkPlan{}, fmt.Sprintf("cannot read %s: %v", hostRoot, err)
	}
	plan.device = dev
	if device != "" && dev != device {
		return walkPlan{}, fmt.Sprintf("%s is on device %s, not %s - give a root on that device to search it", hostRoot, dev, device)
	}
	return plan, ""
}

// hostPrefix is what the agent has to put in front of a host path to reach it.
// An agent in a pod has its own root, and the host's is reachable only through
// pid 1's - /proc/1/root. Empty when the agent already shares that namespace, as
// it does running directly on a node.
func hostPrefix(procRoot string) string {
	self, one := mountNS(procRoot, "self"), mountNS(procRoot, "1")
	if self == "" || one == "" || self == one {
		return ""
	}
	return filepath.Join(procRoot, "1", "root")
}

// deviceOf returns a path's "major:minor" device.
func deviceOf(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("no stat for %s", path)
	}
	return deviceString(uint64(st.Dev)), nil
}

// errWalkStop ends a walk early - the budget is spent, or every link the inode
// claims has been found. WalkDir needs an error to unwind; this one is not a
// failure and never leaves the package.
var errWalkStop = errors.New("walk complete")

// walkForInode is `find -inum`, bounded. It stats every entry under the root,
// which is the only way to match an inode on disk, and stops at the first of:
// the budget running out, or every hard link the inode claims being found.
//
// It never crosses onto another filesystem. That is not an optimisation: the
// same inode number on a different device is a different file, so a match found
// there would be wrong, and /proc, /sys and every network mount would be walked
// for nothing.
func walkForInode(plan walkPlan, inode uint64, budget time.Duration) ([]InodeMatch, WalkStats) {
	stats := WalkStats{Ran: true, Root: plan.hostRoot, Device: plan.device}
	start := time.Now()
	deadline := start.Add(budget)

	var matches []InodeMatch
	var links uint64 // how many paths the inode says it has; 0 until found
	var seen uint64

	err := filepath.WalkDir(plan.agentRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory or a file that vanished mid-walk is
			// skipped: a lookup over a live filesystem cannot expect either.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// The clock is checked every so often rather than per entry: on a tree
		// of millions, time.Now() per file is itself measurable.
		seen++
		if seen%512 == 0 && time.Now().After(deadline) {
			stats.TimedOut = true
			return errWalkStop
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		onDevice := deviceString(uint64(st.Dev)) == plan.device

		if d.IsDir() {
			if path != plan.agentRoot && !onDevice {
				return fs.SkipDir
			}
			stats.Dirs++
		} else {
			stats.Files++
		}
		if st.Ino != inode || !onDevice {
			return nil
		}

		hostPath := path
		if plan.prefix != "" {
			hostPath = strings.TrimPrefix(path, plan.prefix)
		}
		match := InodeMatch{
			Path:     hostPath,
			Device:   plan.device,
			FromWalk: true,
		}
		if plan.prefix != "" {
			match.HostPath = path
		}
		matches = append(matches, match)

		// A directory has one path, so that is the whole answer. A file has as
		// many as its link count, and once they are all found there is nothing
		// left to look for - which is what makes the common nlink=1 case stop
		// at the first hit instead of walking the rest of the disk.
		if d.IsDir() {
			return errWalkStop
		}
		links = uint64(st.Nlink)
		if uint64(len(matches)) >= links {
			return errWalkStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, errWalkStop) {
		stats.Note = err.Error()
	}
	stats.Seconds = time.Since(start).Seconds()
	return matches, stats
}

// mergeMatches folds walk results into the /proc ones. A path found both ways is
// the held answer and keeps its holders; a path only the walk found is added,
// which is how a file nothing has open, or a hard link nobody opened, shows up.
func mergeMatches(held, walked []InodeMatch, procRoot string) []InodeMatch {
	mounts := readMounts(procRoot)
	seen := make(map[string]bool, len(held))
	for _, m := range held {
		seen[m.Device+"\x00"+m.Path] = true
	}
	for _, m := range walked {
		if seen[m.Device+"\x00"+m.Path] {
			continue
		}
		seen[m.Device+"\x00"+m.Path] = true
		m.Mount = mounts[m.Device]
		held = append(held, m)
	}
	sortMatches(held)
	return held
}

// inodeHit is one place an inode was found, before hits are grouped by path.
type inodeHit struct {
	path    string
	device  string
	deleted bool
	holder  InodeHolder
}

// fdHits returns the open file descriptors of one process that carry inode.
// Sockets and pipes are reported too: they have inodes, they turn up in BPF
// maps, and "socket:[12345]" held by a named process is a real answer.
func fdHits(procDir string, inode uint64, device string) []inodeHit {
	fdDir := filepath.Join(procDir, "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return nil // process gone, or not readable without hostPID/privileges
	}

	var hits []inodeHit
	for _, fd := range fds {
		fdPath := filepath.Join(fdDir, fd.Name())
		// Stat, not Lstat: an fd entry is a magic symlink, and the inode being
		// looked for belongs to what it points at, not to the link.
		fi, err := os.Stat(fdPath)
		if err != nil {
			continue // closed under us, or a target that cannot be stat'ed
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Ino != inode {
			continue
		}
		dev := deviceString(uint64(st.Dev))
		if device != "" && dev != device {
			continue
		}
		target, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}
		path, deleted := strings.CutSuffix(target, " (deleted)")
		hits = append(hits, inodeHit{
			path:    path,
			device:  dev,
			deleted: deleted,
			holder:  InodeHolder{PID: pidOf(procDir), Source: sourceFD, FD: fd.Name()},
		})
	}
	return hits
}

// mapsHits returns the file-backed mappings of one process that carry inode.
// /proc/<pid>/maps prints the device and inode beside the pathname, so this
// costs one file read per process and no stat calls at all - which is what makes
// scanning every process on a node affordable.
func mapsHits(procDir string, inode uint64, device string) []inodeHit {
	f, err := os.Open(filepath.Join(procDir, "maps"))
	if err != nil {
		return nil
	}
	defer f.Close()

	var hits []inodeHit
	seen := map[string]bool{} // one file is mapped as several segments
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		dev, ino, path, ok := parseMapsLine(sc.Text())
		if !ok || ino != inode || path == "" {
			continue
		}
		if device != "" && dev != device {
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		clean, deleted := strings.CutSuffix(path, " (deleted)")
		hits = append(hits, inodeHit{
			path:    clean,
			device:  dev,
			deleted: deleted,
			holder:  InodeHolder{PID: pidOf(procDir), Source: sourceMap},
		})
	}
	return hits
}

// parseMapsLine pulls the device, inode and pathname out of one /proc/<pid>/maps
// line:
//
//	7f1c8b4000-7f1c8b6000 r-xp 00000000 fd:01 1179921  /usr/lib/libc.so.6
//
// The pathname is the whole rest of the line - a filename may contain spaces -
// so the five fields before it are taken one at a time rather than by splitting
// the line up. The device is printed in hex there and comes back decimal, to
// match what a stat of an fd reports.
func parseMapsLine(line string) (device string, inode uint64, path string, ok bool) {
	rest := line
	var fields [5]string
	for i := range fields {
		rest = strings.TrimLeft(rest, " ")
		j := strings.IndexByte(rest, ' ')
		if j < 0 {
			// Only the last field may end the line, and then there is no path.
			if i != len(fields)-1 || rest == "" {
				return "", 0, "", false
			}
			fields[i], rest = rest, ""
			break
		}
		fields[i], rest = rest[:j], rest[j+1:]
	}

	major, minor, ok := strings.Cut(fields[3], ":")
	if !ok {
		return "", 0, "", false
	}
	maj, err := strconv.ParseUint(major, 16, 32)
	if err != nil {
		return "", 0, "", false
	}
	min, err := strconv.ParseUint(minor, 16, 32)
	if err != nil {
		return "", 0, "", false
	}
	inode, err = strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return "", 0, "", false
	}
	return fmt.Sprintf("%d:%d", maj, min), inode, strings.TrimLeft(rest, " "), true
}

// deviceString renders a device number the way /proc reports mounts: decimal
// "major:minor".
func deviceString(dev uint64) string {
	return fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev))
}

// pidOf reads the pid back out of a /proc/<pid> path.
func pidOf(procDir string) uint32 {
	pid, _ := strconv.ParseUint(filepath.Base(procDir), 10, 32)
	return uint32(pid)
}

// readMounts maps "major:minor" to a mount point, so a match can say which
// filesystem it was found on. Read from pid 1, whose mount table is the host's
// when the agent can see host pids; several mounts may share a device (bind
// mounts), and the first one named wins.
func readMounts(procRoot string) map[string]string {
	mounts := map[string]string{}
	for _, pid := range []string{"1", "self"} {
		f, err := os.Open(filepath.Join(procRoot, pid, "mountinfo"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// 36 35 98:0 /mnt1 /mnt2 rw,noatime - ext3 /dev/root rw
			//       ^dev  ^root ^mount point
			fields := strings.Fields(sc.Text())
			if len(fields) < 5 {
				continue
			}
			if _, ok := mounts[fields[2]]; !ok {
				mounts[fields[2]] = fields[4]
			}
		}
		f.Close()
		if len(mounts) > 0 {
			return mounts
		}
	}
	return mounts
}

// mountNS returns the mount namespace of a process, as the "mnt:[4026531840]"
// string /proc renders. Empty when it cannot be read.
func mountNS(procRoot, pid string) string {
	ns, err := os.Readlink(filepath.Join(procRoot, pid, "ns", "mnt"))
	if err != nil {
		return ""
	}
	return ns
}

// hostPath returns the path prefixed so the agent can reach it, for a holder
// living in another mount namespace - a container's /usr/bin/foo is not the
// agent's, but it is always at /proc/<pid>/root/usr/bin/foo. Empty when the
// holder shares the agent's namespace (the path is already reachable) or when
// there is nothing to prefix, as for "socket:[12345]".
func hostPath(procRoot string, pid uint32, path, selfNS string) string {
	if selfNS == "" || !strings.HasPrefix(path, "/") {
		return ""
	}
	id := strconv.FormatUint(uint64(pid), 10)
	if ns := mountNS(procRoot, id); ns == "" || ns == selfNS {
		return ""
	}
	return filepath.Join(procRoot, id, "root", path)
}

// ProcessDetail is what /proc knows about one pid.
type ProcessDetail struct {
	Found   bool
	PID     uint32
	Comm    string
	State   string
	PPID    uint32
	UID     string
	Cmdline string
	Exe     string
	Cgroup  string
}

// describeProcess reads one process's identity out of procRoot. Every field is
// best-effort: a process may exit mid-read, and an unprivileged agent can see
// that a pid exists without being able to read its exe.
func describeProcess(procRoot string, pid uint32) ProcessDetail {
	procDir := filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10))
	status, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err != nil {
		return ProcessDetail{PID: pid}
	}

	d := ProcessDetail{Found: true, PID: pid}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Name":
			d.Comm = value
		case "State":
			d.State = value
		case "PPid":
			if ppid, err := strconv.ParseUint(value, 10, 32); err == nil {
				d.PPID = uint32(ppid)
			}
		case "Uid":
			// "real effective saved fs" - the real uid is the one that answers
			// "who is this running as".
			if f := strings.Fields(value); len(f) > 0 {
				d.UID = f[0]
			}
		}
	}

	if b, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
		// Arguments are NUL-separated and NUL-terminated; a kernel thread has
		// none at all, which is itself worth seeing as an empty command line.
		d.Cmdline = strings.Join(strings.FieldsFunc(string(b), func(r rune) bool { return r == 0 }), " ")
	}
	if exe, err := os.Readlink(filepath.Join(procDir, "exe")); err == nil {
		d.Exe = exe
	}
	d.Cgroup = readCgroup(procDir)
	return d
}

// readCgroup returns the process's unified (cgroup v2) path - the "0::" line,
// which is the one a k8s pod's slice shows up in. Falls back to the first entry
// on a v1-only node, where the hierarchy id and controllers come first.
func readCgroup(procDir string) string {
	b, err := os.ReadFile(filepath.Join(procDir, "cgroup"))
	if err != nil {
		return ""
	}
	var first string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return path
		}
		// "<id>:<controllers>:<path>"
		if parts := strings.SplitN(line, ":", 3); len(parts) == 3 && first == "" {
			first = parts[2]
		}
	}
	return first
}
