package inspector

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ProcessResources is what the kernel has accounted to a process and to its
// cgroup so far - the numbers `systemctl status` prints for a service. They are
// counters the kernel keeps anyway, so reading them instruments nothing.
type ProcessResources struct {
	UserCPU   time.Duration
	SystemCPU time.Duration
	RSS       uint64 // bytes
	PeakRSS   uint64 // bytes
	Threads   uint32
	Cgroup    CgroupResources
}

// CgroupResources is one cgroup v2 directory's accounting. A file the kernel
// does not have for this cgroup reads as zero - see the proto.
type CgroupResources struct {
	Note string

	MemoryCurrent      uint64
	MemoryPeak         uint64
	MemoryMax          uint64 // 0: no limit
	MemoryInactiveFile uint64

	CPUUsage     time.Duration
	CPUUser      time.Duration
	CPUSystem    time.Duration
	CPUQuota     time.Duration // 0: no limit
	CPUPeriod    time.Duration
	NrThrottled  uint64
	CPUThrottled time.Duration

	Tasks    uint64
	TasksMax uint64 // 0: no limit
}

// ProcessResources reads the resources of several processes at once - the
// loaders list's rows. A pid that is gone has no entry.
func (i *Inspector) ProcessResources(pids []uint32) map[uint32]ProcessResources {
	return processResources("/proc", pids)
}

// processResources reads every pid's cgroup path in one trip into the node's
// cgroup namespace: entering it costs an OS thread, which is thrown away
// afterwards, so a page of loaders must not pay that per row.
func processResources(procRoot string, pids []uint32) map[uint32]ProcessResources {
	procDir := func(pid uint32) string { return filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10)) }
	paths := make(map[uint32]string, len(pids))
	ns := readCgroupPaths(procRoot, func() {
		for _, pid := range pids {
			paths[pid] = readCgroup(procDir(pid))
		}
	})
	root := cgroupV2Root(procRoot)

	out := make(map[uint32]ProcessResources, len(pids))
	for _, pid := range pids {
		r, ok := readProcessResources(procDir(pid))
		if !ok {
			continue
		}
		r.Cgroup = cgroupResources(root, paths[pid], ns)
		out[pid] = r
	}
	return out
}

// readProcessResources reads the process half: memory and threads out of
// status, CPU time out of stat. ok is false when the process is gone.
func readProcessResources(procDir string) (r ProcessResources, ok bool) {
	status, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err != nil {
		return r, false
	}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "VmRSS":
			r.RSS = parseKB(value)
		case "VmHWM":
			r.PeakRSS = parseKB(value)
		case "Threads":
			if n, err := strconv.ParseUint(value, 10, 32); err == nil {
				r.Threads = uint32(n)
			}
		}
	}
	r.UserCPU, r.SystemCPU = readCPUTimes(procDir)
	return r, true
}

// userHZ is the unit /proc/<pid>/stat counts CPU time in. It is USER_HZ, not
// the kernel's own tick rate: the kernel scales to it before writing the file,
// and it is 100 on every architecture Linux runs on - it is part of the ABI,
// which is why it can be a constant here rather than a sysconf(_SC_CLK_TCK).
const userHZ = 100

// readCPUTimes reads utime and stime out of /proc/<pid>/stat. The comm field
// sits in parentheses and may itself hold spaces and parentheses, so the fields
// are counted from the last ')' rather than split from the start.
func readCPUTimes(procDir string) (user, system time.Duration) {
	b, err := os.ReadFile(filepath.Join(procDir, "stat"))
	if err != nil {
		return 0, 0
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, 0
	}
	// Field 3 (state) is the first after the comm, so utime (14) and stime
	// (15) are the 12th and 13th.
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 13 {
		return 0, 0
	}
	tick := time.Second / userHZ
	u, _ := strconv.ParseUint(f[11], 10, 64)
	s, _ := strconv.ParseUint(f[12], 10, 64)
	return time.Duration(u) * tick, time.Duration(s) * tick
}

// parseKB reads a /proc/<pid>/status size, e.g. "  1234 kB".
func parseKB(value string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSuffix(value, " kB"), 10, 64)
	return n * 1024
}

// cgroupResources finds a process's cgroup directory under root, the node's
// cgroup v2 mount as cgroupV2Root reaches it, and reads it. path is what
// /proc/<pid>/cgroup said, and ns is what it took to read it: a path the node's
// namespace could not be entered for is the agent's own spelling, and joined to
// the node's mount it would name some other cgroup, or none.
func cgroupResources(root, path string, ns cgroupNS) CgroupResources {
	switch {
	case path == "":
		return CgroupResources{Note: "the process's cgroup could not be read"}
	case ns.Note != "":
		return CgroupResources{Note: ns.Note}
	}
	if root == "" {
		return CgroupResources{Note: "no cgroup v2 hierarchy is mounted on the node"}
	}
	dir := filepath.Join(root, path)
	if dir != root && !strings.HasPrefix(dir, root+"/") {
		return CgroupResources{Note: "the cgroup path " + path + " is outside the cgroup v2 hierarchy"}
	}
	if _, err := os.Stat(dir); err != nil {
		return CgroupResources{Note: "cannot open the cgroup: " + err.Error()}
	}
	return readCgroupDir(dir)
}

// readCgroupDir reads the cgroup v2 interface files systemctl status and the
// kubelet read. Each is best-effort: which exist depends on the controllers
// enabled for this cgroup and on the kernel's age.
func readCgroupDir(dir string) CgroupResources {
	var r CgroupResources
	r.MemoryCurrent = readCgroupValue(dir, "memory.current")
	r.MemoryPeak = readCgroupValue(dir, "memory.peak")
	r.MemoryMax = readCgroupValue(dir, "memory.max")
	r.MemoryInactiveFile = readKeyed(dir, "memory.stat")["inactive_file"]

	usec := func(n uint64) time.Duration { return time.Duration(n) * time.Microsecond }
	stat := readKeyed(dir, "cpu.stat")
	r.CPUUsage = usec(stat["usage_usec"])
	r.CPUUser = usec(stat["user_usec"])
	r.CPUSystem = usec(stat["system_usec"])
	r.NrThrottled = stat["nr_throttled"]
	r.CPUThrottled = usec(stat["throttled_usec"])
	if b, err := os.ReadFile(filepath.Join(dir, "cpu.max")); err == nil {
		// "$QUOTA $PERIOD", with "max" for no quota.
		if f := strings.Fields(string(b)); len(f) == 2 {
			quota, _ := strconv.ParseUint(f[0], 10, 64)
			period, _ := strconv.ParseUint(f[1], 10, 64)
			r.CPUQuota, r.CPUPeriod = usec(quota), usec(period)
		}
	}

	r.Tasks = readCgroupValue(dir, "pids.current")
	r.TasksMax = readCgroupValue(dir, "pids.max")
	return r
}

// readCgroupValue reads a single-number cgroup file. "max", the spelling for no
// limit, reads as 0, as does a file that is not there.
func readCgroupValue(dir, name string) uint64 {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// readKeyed reads a flat-keyed cgroup file - "key value" per line, as cpu.stat
// and memory.stat are.
func readKeyed(dir, name string) map[string]uint64 {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil
	}
	out := map[string]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		if key, value, ok := strings.Cut(line, " "); ok {
			if n, err := strconv.ParseUint(value, 10, 64); err == nil {
				out[key] = n
			}
		}
	}
	return out
}
