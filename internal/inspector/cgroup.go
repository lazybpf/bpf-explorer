package inspector

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Cgroups is which hierarchy the node runs and how the kubelet names paths in
// it, with the evidence for both.
type Cgroups struct {
	Mode         string // "unified" (v2), "legacy" (v1), "hybrid"
	ModeSource   string
	Driver       string // "systemd", "cgroupfs", empty when nothing said
	DriverSource string
	AgentPath    string // the agent's own cgroup, as the node names it
	ExamplePath  string // one pod container's cgroup path on this node
	ExamplePID   uint32
	ExampleComm  string
	// Namespaced says the agent is in a cgroup namespace of its own, so the
	// paths above had to be read from the node's - see cgroupNS. NamespaceNote
	// says why they could not be, on the runs where that fails: the paths are
	// then the agent's own view, and must not be read as the node's.
	Namespaced    bool
	NamespaceNote string
}

// defaultKubeletConfig is where the kubelet reads its configuration from when
// --config does not say otherwise.
const defaultKubeletConfig = "/var/lib/kubelet/config.yaml"

// readCgroup returns a process's unified (cgroup v2) path - the "0::" line,
// which is the one a k8s pod's slice shows up in. Falls back to the first entry
// on a v1-only node, where the hierarchy id and controllers come first.
//
// The path is as the READER's own cgroup namespace spells it, which is not
// always as the node does - so where it matters this is called from inside
// readCgroupPaths, which is what puts the reader on the node's side.
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

// cgroupNS is what the agent's own cgroup namespace stands between it and the
// node's cgroup paths, and what it took to read past it.
//
// The kernel writes the paths in /proc/<pid>/cgroup relative to the READER's
// cgroup namespace root, not the node's. A container is normally given a
// namespace of its own - it is how /sys/fs/cgroup inside one can be the
// container's own cgroup - so an agent in a pod reads its own cgroup as "/" and
// a pod elsewhere on the node as "/../../../../../kubepods.slice/...". Neither
// string exists on the node, and the second is the one the node tab must get
// right: it is shown as what an agent resolving containers has to parse.
//
// Nothing in the agent's own namespace says where it sits on the node - the
// mount table's root field is translated the same way, reading "/" for the
// container's own mount - so the paths cannot be computed back. They are read
// from the other side instead: the reads run on a thread that has joined the
// node's own cgroup namespace, where no translation happens at all.
type cgroupNS struct {
	// Namespaced says the agent is in a cgroup namespace the node's init is not.
	Namespaced bool
	// Note says why the paths are still the agent's own, when they are: joining
	// the node's namespace needs CAP_SYS_ADMIN, which the DaemonSet has and a
	// developer's unprivileged run does not.
	Note string
}

// readCgroupPaths runs read where cgroup paths come out as the node writes them,
// and reports what stood in the way. An agent that shares the node's cgroup
// namespace - every unprivileged local run - reads them directly, on this
// thread: there is nothing to join, and nothing to explain.
func readCgroupPaths(procRoot string, read func()) cgroupNS {
	self, okSelf := nsInode(filepath.Join(procRoot, "self"), "cgroup")
	init, okInit := nsInode(filepath.Join(procRoot, "1"), "cgroup")
	if !okSelf || !okInit || self == init {
		// Either the agent is in the node's own namespace, or it cannot see
		// init's link to tell - which takes root, so the agent is unprivileged
		// and reading its own /proc, where nothing is displaced either.
		read()
		return cgroupNS{}
	}

	if err := runInCgroupNS(filepath.Join(procRoot, "1", "ns", "cgroup"), read); err != nil {
		read() // displaced, and said to be
		return cgroupNS{
			Namespaced: true,
			Note: "the node's cgroup namespace could not be entered (" + err.Error() +
				"), so these are the paths as the agent's own namespace spells them",
		}
	}
	return cgroupNS{Namespaced: true}
}

// runInCgroupNS runs fn on a thread that has joined the cgroup namespace named
// by nsPath - what `nsenter --cgroup -t 1` does, for the length of one call.
//
// The thread is locked and never unlocked: a thread that has been moved into
// another namespace must not go back into the runtime's pool, and letting the
// goroutine return while it is still locked is what has the runtime throw it
// away instead. Only the calling thread's namespace changes, so nothing else in
// the agent is affected while this runs.
func runInCgroupNS(nsPath string, fn func()) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()

		f, err := os.Open(nsPath)
		if err != nil {
			runtime.UnlockOSThread() // nothing happened to this thread; keep it
			result <- err
			return
		}
		defer f.Close()

		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWCGROUP); err != nil {
			runtime.UnlockOSThread()
			result <- err
			return
		}
		fn()
		result <- nil
	}()
	return <-result
}

// readCgroups reports the node's cgroup layout: which hierarchy is mounted,
// which driver named the paths in it, and the two paths that show it.
func readCgroups(procRoot, root string, ns cgroupNS, agentPath string, components []Component, sample cgroupSample) Cgroups {
	cg := Cgroups{
		AgentPath:     agentPath,
		ExamplePath:   sample.Path,
		ExamplePID:    sample.PID,
		ExampleComm:   sample.Comm,
		Namespaced:    ns.Namespaced,
		NamespaceNote: ns.Note,
	}
	// A path that still climbs was read through a namespace after all - no
	// cgroup is ever named "..", so this is displacement the check above could
	// not see, and it must not be shown as if it were the node's own.
	if cg.NamespaceNote == "" && (strings.Contains(cg.AgentPath, "/..") || strings.Contains(cg.ExamplePath, "/..")) {
		cg.Namespaced = true
		cg.NamespaceNote = "these paths climb out of a cgroup namespace the agent could not identify, so they are its own view rather than the node's"
	}
	cg.Mode, cg.ModeSource = cgroupMode(procRoot)
	cg.Driver, cg.DriverSource = cgroupDriver(procRoot, root, components, sample)
	return cg
}

// cgroupMode reads the node's cgroup mounts out of a mount table. Pid 1's is
// read first, as readMounts does and for the same reason: with hostPID that is
// the node's init and its table is the host's, while the agent's own
// /sys/fs/cgroup is whatever its runtime handed the container.
func cgroupMode(procRoot string) (mode, source string) {
	for _, pid := range []string{"1", "self"} {
		var v1, v2 int
		eachMount(procRoot, pid, func(e mountEntry) bool {
			switch e.FSType {
			case "cgroup":
				v1++
			case "cgroup2":
				v2++
			}
			return true
		})

		path := filepath.Join(procRoot, pid, "mountinfo")
		switch {
		case v2 > 0 && v1 > 0:
			// cgroup2 alongside v1 controllers: the unified tree is mounted, but
			// the controllers a container is accounted by are still on v1.
			return "hybrid", path
		case v2 > 0:
			return "unified", path
		case v1 > 0:
			return "legacy", path
		}
	}
	return "", ""
}

// cgroupDriver reports which driver named the node's pod cgroups, and what
// settled it. The kubelet is asked first - its flag, then its config file, since
// that is the setting itself - and the pod paths answer when it cannot be
// reached. Where both are known and disagree, the source says so: a config
// changed without a restart leaves the paths right and the file wrong.
func cgroupDriver(procRoot, root string, components []Component, sample cgroupSample) (driver, source string) {
	observed := driverFromPath(sample.Path)

	if kubelet := findComponent(components, "kubelet"); kubelet != nil {
		if d := flagValue(kubelet.Cmdline, "--cgroup-driver"); d != "" {
			return d, withDisagreement(fmt.Sprintf("--cgroup-driver on kubelet(%d)", kubelet.PID), d, observed)
		}
		if d, path := kubeletConfigDriver(procRoot, root, *kubelet); d != "" {
			return d, withDisagreement("cgroupDriver in "+path, d, observed)
		}
	}
	if observed != "" {
		return observed, "the shape of the pod cgroup path below"
	}
	return "", ""
}

// driverFromPath reads the driver off a pod's cgroup path. systemd gives every
// level a .slice or .scope suffix and spells the whole tree into each name
// (kubepods-burstable-pod<uid>.slice); cgroupfs nests plain directories
// (/kubepods/burstable/pod<uid>). Telling those apart is most of what container
// resolution from a cgroup has to get right.
func driverFromPath(path string) string {
	if path == "" {
		return ""
	}
	if strings.Contains(path, ".slice") || strings.Contains(path, ".scope") {
		return "systemd"
	}
	return "cgroupfs"
}

// withDisagreement notes a driver the node's own paths contradict, rather than
// letting a stale setting be reported as the truth on its own.
func withDisagreement(source, driver, observed string) string {
	if observed == "" || observed == driver {
		return source
	}
	return source + ", though the pod cgroup path below reads as " + observed
}

// kubeletConfigDriver reads cgroupDriver out of the kubelet's config file. The
// file is looked for through the kubelet's own root first: /var/lib/kubelet is
// on the node, and the agent's container has no such path of its own.
func kubeletConfigDriver(procRoot, root string, kubelet Component) (driver, source string) {
	config := flagValue(kubelet.Cmdline, "--config")
	if config == "" {
		config = defaultKubeletConfig
	}
	for _, path := range []string{
		filepath.Join(procRoot, strconv.FormatUint(uint64(kubelet.PID), 10), "root", config),
		filepath.Join(root, config),
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if d := topLevelYAMLValue(b, "cgroupDriver"); d != "" {
			return d, path
		}
	}
	return "", ""
}

// topLevelYAMLValue pulls one top-level scalar out of a YAML file without
// parsing YAML. KubeletConfiguration writes cgroupDriver at the top level, and
// requiring the key to start the line is what keeps a nested key of the same
// name - under a section this does not understand - from answering in its place.
func topLevelYAMLValue(b []byte, key string) string {
	for _, line := range strings.Split(string(b), "\n") {
		value, ok := strings.CutPrefix(line, key+":")
		if !ok {
			continue
		}
		if comment := strings.Index(value, "#"); comment >= 0 {
			value = value[:comment]
		}
		return strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return ""
}

// flagValue returns the value of a command-line flag, in either spelling:
// "--flag=value" or "--flag value".
func flagValue(cmdline, flag string) string {
	fields := strings.Fields(cmdline)
	for i, f := range fields {
		if value, ok := strings.CutPrefix(f, flag+"="); ok {
			return value
		}
		if f == flag && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
