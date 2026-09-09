package inspector

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// writeProcess lays out a fake /proc/<pid> for the node scan: the three files it
// reads about every process, and optionally the exe link it reads a version out
// of.
func writeProcess(t *testing.T, root, pid, comm, cmdline, cgroup, exe string) {
	t.Helper()
	procDir := filepath.Join(root, pid)
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"comm":    comm + "\n",
		"cmdline": strings.ReplaceAll(cmdline, " ", "\x00"),
		"cgroup":  "0::" + cgroup + "\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(procDir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if exe != "" {
		if err := os.Symlink(exe, filepath.Join(procDir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
}

// TestScanNodeProcessesFindsComponents covers the roster: the daemons are named
// and the per-container shims are not, which is what keeps the list a list of
// the node's runtime rather than of everything running on it.
func TestScanNodeProcessesFindsComponents(t *testing.T) {
	root := t.TempDir()
	writeProcess(t, root, "1", "systemd", "/sbin/init", "/init.scope", "")
	writeProcess(t, root, "900", "kubelet", "/usr/bin/kubelet --config=/var/lib/kubelet/config.yaml", "/system.slice/kubelet.service", "")
	writeProcess(t, root, "800", "containerd", "/usr/bin/containerd", "/system.slice/containerd.service", "")
	// comm is truncated to 15 characters by the kernel, so a shim can never look
	// like the daemon - there is one of these per container.
	writeProcess(t, root, "1200", "containerd-shim", "/usr/bin/containerd-shim-runc-v2 -id abc", "/system.slice/run-abc.scope", "")
	writeProcess(t, root, "1300", "nginx", "nginx: master process", "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod9f.slice/cri-containerd-77.scope", "")

	components, sample := scanNodeProcesses(root)

	var got []string
	for _, c := range components {
		got = append(got, c.Name)
	}
	// Sorted by name, so the order does not shift between calls the way /proc's
	// own does.
	if len(got) != 2 || got[0] != "containerd" || got[1] != "kubelet" {
		t.Fatalf("components %v, want [containerd kubelet]", got)
	}
	if components[0].PID != 800 {
		t.Errorf("containerd pid %d, want 800", components[0].PID)
	}
	if components[1].Cmdline != "/usr/bin/kubelet --config=/var/lib/kubelet/config.yaml" {
		t.Errorf("kubelet cmdline %q, want the flags it was started with", components[1].Cmdline)
	}

	// The sample is a pod's cgroup, not the agent's own or a system service's:
	// only a kubepods path says how the kubelet names things.
	if !strings.HasPrefix(sample.Path, "/kubepods.slice/") {
		t.Errorf("sample path %q, want the pod cgroup", sample.Path)
	}
	if sample.PID != 1300 || sample.Comm != "nginx" {
		t.Errorf("sample from %s(%d), want nginx(1300)", sample.Comm, sample.PID)
	}
}

// TestScanNodeProcessesNoPods checks a node with nothing scheduled on it leaves
// the sample empty rather than offering a system slice as if it were a pod's.
func TestScanNodeProcessesNoPods(t *testing.T) {
	root := t.TempDir()
	writeProcess(t, root, "800", "containerd", "/usr/bin/containerd", "/system.slice/containerd.service", "")

	_, sample := scanNodeProcesses(root)
	if sample.Path != "" {
		t.Errorf("sample %q, want none - no pod is running", sample.Path)
	}
}

// TestVersionFromLDFlags uses the flags real releases are linked with: this is
// where containerd and moby keep the version they report, and getting the -X
// spelling wrong loses it silently.
func TestVersionFromLDFlags(t *testing.T) {
	tests := []struct {
		name       string
		ldflags    string
		want       string
		wantSource string
	}{
		{
			"containerd",
			`-X github.com/containerd/containerd/v2/version.Version=v2.3.5 -X github.com/containerd/containerd/v2/version.Revision=1294c24 -X github.com/containerd/containerd/v2/version.Package=containerd -s -w `,
			"v2.3.5", "-X github.com/containerd/containerd/v2/version.Version",
		},
		{
			// Quoted values, one of which has spaces in it: split on whitespace
			// alone and the version comes out of the wrong -X.
			"dockerd",
			`-w -X "github.com/moby/moby/v2/dockerversion.Version=29.8.0" -X "github.com/moby/moby/v2/dockerversion.GitCommit=3ce5872" -X "github.com/moby/moby/v2/dockerversion.PlatformName=Docker Engine - Community"`,
			"29.8.0", "-X github.com/moby/moby/v2/dockerversion.Version",
		},
		{
			// The Kubernetes components stamp gitVersion, and set the plain
			// Version elsewhere in the same link.
			"kubelet",
			`-X k8s.io/component-base/version.gitVersion=v1.31.4 -X k8s.io/component-base/version.gitCommit=abc123 -X k8s.io/client-go/pkg/version.gitVersion=v1.31.4`,
			"v1.31.4", "-X k8s.io/component-base/version.gitVersion",
		},
		{"nothing stamped", `-s -w`, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			version, source := versionFromLDFlags([]debug.BuildSetting{
				{Key: "-tags", Value: "urfave_cli_no_docs"},
				{Key: "-ldflags", Value: tc.ldflags},
			})
			if version != tc.want {
				t.Errorf("version %q, want %q", version, tc.want)
			}
			if source != tc.wantSource {
				t.Errorf("source %q, want %q", source, tc.wantSource)
			}
		})
	}
}

func TestSplitQuoted(t *testing.T) {
	got := splitQuoted(`-w -X "pkg.Name=Docker Engine - Community" -X 'pkg.V=1.0'`)
	want := []string{"-w", "-X", "pkg.Name=Docker Engine - Community", "-X", "pkg.V=1.0"}
	if len(got) != len(want) {
		t.Fatalf("split into %d fields %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestReadBuildFacts reads a binary that is certainly there and certainly Go:
// the test binary itself. It has no version stamp of its own, which is the case
// worth pinning - a binary built without one must say so rather than show the
// toolchain's placeholder as a version.
func TestReadBuildFacts(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no executable path: %v", err)
	}

	facts := readBuildFacts(exe)
	if facts.GoVersion == "" {
		t.Errorf("no Go version read from %s", exe)
	}
	if facts.Module == "" {
		t.Errorf("no module read from %s", exe)
	}
	if facts.Version != "" {
		t.Errorf("version %q, want none - a test binary carries no version stamp", facts.Version)
	}
	if facts.Note == "" {
		t.Errorf("a missing version must come with the note that says why")
	}
}

func TestReadBuildFactsUnreadable(t *testing.T) {
	facts := readBuildFacts(filepath.Join(t.TempDir(), "gone"))
	if facts.Note == "" || facts.Version != "" {
		t.Errorf("facts %+v, want only a note about the missing binary", facts)
	}

	// A component written in C - crun, and some vendors' runtimes - records no
	// build information, which is an answer and not a failure.
	notGo := filepath.Join(t.TempDir(), "crun")
	if err := os.WriteFile(notGo, []byte("\x7fELF not really"), 0o755); err != nil {
		t.Fatal(err)
	}
	if facts := readBuildFacts(notGo); facts.Note == "" {
		t.Errorf("facts %+v, want the note that there is no Go build information", facts)
	}
}

func TestIsVersion(t *testing.T) {
	for _, v := range []string{"v2.3.5", "29.8.0", "v1.31.4"} {
		if !isVersion(v) {
			t.Errorf("isVersion(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "(devel)", "v0.0.0"} {
		if isVersion(v) {
			t.Errorf("isVersion(%q) = true, want false - it is a placeholder", v)
		}
	}
}

// TestReadOSImage checks the node's own file wins over the agent's, which is the
// difference between naming the node and naming the container image the agent
// ships in.
func TestReadOSImage(t *testing.T) {
	procRoot, root := t.TempDir(), t.TempDir()
	writeOSRelease(t, filepath.Join(procRoot, "1", "root", "etc"), `PRETTY_NAME="Flatcar Container Linux by Kinvolk"`)
	writeOSRelease(t, filepath.Join(root, "etc"), `PRETTY_NAME="Distroless"`)

	image, source := readOSImage(procRoot, root)
	if image != "Flatcar Container Linux by Kinvolk" {
		t.Errorf("os image %q, want the node's", image)
	}
	if !strings.Contains(source, "/1/root/etc/os-release") {
		t.Errorf("source %q, want the file read through pid 1's root", source)
	}

	// Without pid 1's root - an unprivileged agent - the agent's own file is all
	// there is, and the source is what says so.
	image, source = readOSImage(t.TempDir(), root)
	if image != "Distroless" || !strings.HasSuffix(source, "/etc/os-release") {
		t.Errorf("os image %q from %q, want the agent's own file named as such", image, source)
	}

	if image, _ := readOSImage(t.TempDir(), t.TempDir()); image != "" {
		t.Errorf("os image %q, want none - there is no file to read", image)
	}
}

func writeOSRelease(t *testing.T, dir, contents string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "os-release"), []byte("ID=linux\n"+contents+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDescribeNodeReadsWhatItCan checks the whole call against a node the agent
// can only half see: the facts that are there come back, and the ones that are
// not come back empty rather than failing the call.
func TestDescribeNodeReadsWhatItCan(t *testing.T) {
	procRoot, root := t.TempDir(), t.TempDir()
	writeProcess(t, procRoot, "900", "kubelet", "/usr/bin/kubelet --cgroup-driver=cgroupfs", "/system.slice/kubelet.service", "")
	writeProcess(t, procRoot, "1300", "nginx", "nginx", "/kubepods/burstable/pod9f/77", "")
	writeMountinfo(t, procRoot, "1", "36 26 0:31 / /sys/fs/cgroup rw shared:9 - cgroup2 cgroup2 rw\n")

	node := describeNode(procRoot, root)

	if node.Kernel.Release == "" || node.Kernel.Arch == "" {
		t.Errorf("kernel %+v, want the running kernel's release and the agent's arch", node.Kernel)
	}
	if node.Cgroups.Mode != "unified" {
		t.Errorf("cgroup mode %q, want unified", node.Cgroups.Mode)
	}
	if node.Cgroups.Driver != "cgroupfs" {
		t.Errorf("cgroup driver %q, want cgroupfs", node.Cgroups.Driver)
	}
	if node.Cgroups.ExamplePath != "/kubepods/burstable/pod9f/77" {
		t.Errorf("example path %q, want the pod cgroup", node.Cgroups.ExamplePath)
	}
	if len(node.Components) != 1 || node.Components[0].Name != "kubelet" {
		t.Fatalf("components %+v, want just the kubelet", node.Components)
	}
	// No exe link in the fake /proc: the version is missing, and says why.
	if c := node.Components[0]; c.Version != "" || c.Note == "" {
		t.Errorf("component %+v, want no version and a note", c)
	}
}
