package inspector

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// NodeDetail is the node's own configuration - the context every other answer is
// read against. A pid or a cgroup id out of a BPF map becomes a container only
// through these facts.
type NodeDetail struct {
	Kernel     Kernel
	Cgroups    Cgroups
	Components []Component
}

// Kernel is what uname reports, plus the node's OS image.
type Kernel struct {
	Release string
	Version string
	Machine string
	// Arch is the agent binary's own GOARCH: the same architecture Machine
	// names, spelled the way Go and container images spell it.
	Arch     string
	OSImage  string
	OSSource string // the file OSImage was read from
}

// Component is one container-runtime or kubelet process on the node.
type Component struct {
	Name          string // comm
	PID           uint32
	Exe           string
	Cmdline       string
	Version       string
	VersionSource string
	Module        string
	GoVersion     string
	Note          string // why there is no version
}

// componentComms are the processes worth naming as the node's container stack,
// matched on comm exactly. The kernel truncates comm to 15 characters, which is
// what keeps the per-container shims out: "containerd-shim-runc-v2" reaches
// /proc as "containerd-shim" and cannot be mistaken for the daemon.
var componentComms = map[string]bool{
	"containerd":  true,
	"dockerd":     true,
	"crio":        true,
	"cri-dockerd": true,
	"podman":      true,
	"kubelet":     true,
	"k3s-server":  true,
	"k3s-agent":   true,
}

// DescribeNode reports the node's kernel, cgroup layout and container stack.
// Every field is best-effort and says where it came from: an agent that cannot
// see host pids, or cannot open another process's binary, still answers - with
// less, and with a note rather than a guess.
func (i *Inspector) DescribeNode() NodeDetail {
	return describeNode("/proc", "/")
}

// describeNode does the work against an injectable /proc and filesystem root.
// root is where a path named on the node - the kubelet's config file - is looked
// for when it cannot be reached through the owning process's own root.
func describeNode(procRoot, root string) NodeDetail {
	// Every cgroup path this page shows is read in one place, from the node's own
	// cgroup namespace: the /proc walk that finds the pod path, and the agent's
	// own. Nothing else in the walk cares which namespace it runs in - a binary
	// and a command line read the same either way.
	var components []Component
	var sample cgroupSample
	var agentPath string
	ns := readCgroupPaths(procRoot, func() {
		components, sample = scanNodeProcesses(procRoot)
		agentPath = readCgroup(filepath.Join(procRoot, "self"))
	})

	return NodeDetail{
		Kernel:     readKernel(procRoot, root),
		Cgroups:    readCgroups(procRoot, root, ns, agentPath, components, sample),
		Components: components,
	}
}

// readKernel fills in uname and the node's OS image. The uname fields are the
// kernel's own and no namespace changes them, so they need no qualification -
// unlike the OS image, which is a file and gets one.
func readKernel(procRoot, root string) Kernel {
	k := Kernel{Arch: runtime.GOARCH}
	var u unix.Utsname
	if err := unix.Uname(&u); err == nil {
		k.Release = utsString(u.Release[:])
		k.Version = utsString(u.Version[:])
		k.Machine = utsString(u.Machine[:])
	}
	k.OSImage, k.OSSource = readOSImage(procRoot, root)
	return k
}

// utsString trims the NUL padding off a Utsname field.
func utsString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// readOSImage returns the node's PRETTY_NAME and the file it came from. Pid 1's
// root is tried first: the agent's own /etc/os-release names the container image
// it ships in, which is the node's answer only when the agent runs on the host.
// Reporting the path is what lets the reader tell those two apart.
func readOSImage(procRoot, root string) (image, source string) {
	for _, path := range []string{
		filepath.Join(procRoot, "1", "root", "etc", "os-release"),
		filepath.Join(root, "etc", "os-release"),
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if name := prettyName(b); name != "" {
			return name, path
		}
	}
	return "", ""
}

// prettyName pulls PRETTY_NAME out of an os-release file, unquoted.
func prettyName(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "PRETTY_NAME=")
		if !ok {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return ""
}

// cgroupSample is one pod container's cgroup path, kept as the evidence for how
// the node names them.
type cgroupSample struct {
	Path string
	PID  uint32
	Comm string
}

// scanNodeProcesses walks /proc once for both answers it holds about the node's
// container stack: the runtime processes themselves, and the first pod cgroup
// path they have put a process in. One pass, since both come from the same
// per-process files - and like every other /proc scan here it is best-effort: a
// process that exits under it is skipped rather than failing the call.
//
// It reads cgroup paths, so it runs where those come out as the node writes
// them - see readCgroupPaths, which is what calls it.
func scanNodeProcesses(procRoot string) ([]Component, cgroupSample) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, cgroupSample{}
	}

	var components []Component
	var sample cgroupSample
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // not a "/proc/<pid>" directory
		}
		procDir := filepath.Join(procRoot, e.Name())
		comm := readComm(procDir)
		if comm == "" {
			continue // gone, or not readable
		}
		if sample.Path == "" {
			if path := readCgroup(procDir); isPodCgroup(path) {
				sample = cgroupSample{Path: path, PID: uint32(pid), Comm: comm}
			}
		}
		if componentComms[comm] {
			components = append(components, describeComponent(procDir, uint32(pid), comm))
		}
	}

	// By name, then pid: a node running two containerds (a k3s one beside the
	// host's) lists them together, and the order does not shift between calls
	// the way /proc's own does.
	sort.Slice(components, func(i, j int) bool {
		if components[i].Name != components[j].Name {
			return components[i].Name < components[j].Name
		}
		return components[i].PID < components[j].PID
	})
	return components, sample
}

// findComponent returns the first component with the given comm - the
// lowest-pid one, since the roster is sorted - or nil. The cgroup driver is read
// off the kubelet this way.
func findComponent(components []Component, name string) *Component {
	for i := range components {
		if components[i].Name == name {
			return &components[i]
		}
	}
	return nil
}

// isPodCgroup says whether a cgroup path is one the kubelet made. Only those
// answer for the driver: every other cgroup on the node - a user session, a
// system service - is named by systemd whatever the kubelet was told to do.
func isPodCgroup(path string) bool {
	return strings.Contains(path, "kubepods")
}

// describeComponent reads one runtime process: what it is, how it was started,
// and what its binary says about itself.
func describeComponent(procDir string, pid uint32, comm string) Component {
	c := Component{Name: comm, PID: pid}
	if b, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
		c.Cmdline = strings.Join(strings.FieldsFunc(string(b), func(r rune) bool { return r == 0 }), " ")
	}
	if exe, err := os.Readlink(filepath.Join(procDir, "exe")); err == nil {
		c.Exe = exe
	}

	// The magic link, not the path it resolves to: /usr/bin/containerd is a path
	// in the runtime's mount namespace, which is not the agent's, while
	// /proc/<pid>/exe opens the running binary from anywhere - including one
	// whose package has been upgraded out from under it.
	b := readBuildFacts(filepath.Join(procDir, "exe"))
	c.Version, c.VersionSource = b.Version, b.VersionSource
	c.Module, c.GoVersion, c.Note = b.Module, b.GoVersion, b.Note
	return c
}

// buildFacts is what a binary records about itself.
type buildFacts struct {
	Version       string
	VersionSource string
	Module        string
	GoVersion     string
	Note          string
}

// readBuildFacts reads a binary's Go build information - the same data
// `go version -m` prints. Every part of the node's container stack is written in
// Go, which is what makes this a version that costs nothing: no CRI socket, no
// exec, no privileges beyond opening the file.
func readBuildFacts(exePath string) buildFacts {
	f, err := os.Open(exePath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return buildFacts{Note: "not permitted to read the binary - opening another process's exe needs root"}
		}
		return buildFacts{Note: "cannot read the binary: " + err.Error()}
	}
	defer f.Close()

	info, err := buildinfo.Read(f)
	if err != nil {
		// A component built in C (crun, and some vendors' runtimes) records
		// nothing of the sort, and that is an answer rather than a failure.
		return buildFacts{Note: "no Go build information in the binary: " + err.Error()}
	}

	facts := buildFacts{Module: info.Main.Path, GoVersion: info.GoVersion}
	if facts.Module == "" {
		facts.Module = info.Path // a binary built outside a module names its package
	}
	if version, key := versionFromLDFlags(info.Settings); version != "" {
		facts.Version, facts.VersionSource = version, key
		return facts
	}
	if isVersion(info.Main.Version) {
		facts.Version, facts.VersionSource = info.Main.Version, "main module version"
		return facts
	}
	facts.Note = "the binary carries no version stamp"
	return facts
}

// versionKeys are the variables a component stamps its own version into with
// -X, by the last segment of the variable name, most specific first: the
// Kubernetes components carry gitVersion, containerd and moby a plain Version.
var versionKeys = []string{"gitVersion", "GitVersion", "Version", "version"}

// versionFromLDFlags digs the version out of the -ldflags the binary was linked
// with, and returns the -X assignment it came from so the answer can be
// attributed. This is where a released containerd or dockerd keeps its version:
// their main module version is the tag they were tagged with at most, and
// "(devel)" at worst.
func versionFromLDFlags(settings []debug.BuildSetting) (version, source string) {
	best := len(versionKeys)
	for _, s := range settings {
		if s.Key != "-ldflags" {
			continue
		}
		for name, value := range xAssignments(s.Value) {
			symbol := name
			if i := strings.LastIndex(name, "."); i >= 0 {
				symbol = name[i+1:]
			}
			for rank, want := range versionKeys {
				if symbol == want && rank < best {
					best, version, source = rank, value, "-X "+name
				}
			}
		}
	}
	return version, source
}

// xAssignments returns the -X "name=value" pairs in a linker flag string. Both
// spellings the go command accepts are handled ("-X name=value" and
// "-X=name=value"), since a binary is stamped by whichever its build system used.
func xAssignments(ldflags string) map[string]string {
	out := map[string]string{}
	fields := splitQuoted(ldflags)
	for i, f := range fields {
		assignment := ""
		switch {
		case f == "-X" && i+1 < len(fields):
			assignment = fields[i+1]
		case strings.HasPrefix(f, "-X="):
			assignment = strings.TrimPrefix(f, "-X=")
		default:
			continue
		}
		if name, value, ok := strings.Cut(assignment, "="); ok {
			out[strings.Trim(name, `"'`)] = strings.Trim(value, `"'`)
		}
	}
	return out
}

// splitQuoted splits on whitespace, keeping a quoted run together. moby links
// with -X "…dockerversion.PlatformName=Docker Engine - Community", and a plain
// Fields() would take that value apart in the middle.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	started := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, started = r, true
		case r == ' ' || r == '\t':
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

// isVersion rejects the placeholders the toolchain writes when a build carried
// no version of its own, so they are not shown as if they were one.
func isVersion(v string) bool {
	switch v {
	case "", "(devel)", "(unknown)", "v0.0.0", "v0.0.0-00010101000000-000000000000":
		return false
	}
	return true
}
