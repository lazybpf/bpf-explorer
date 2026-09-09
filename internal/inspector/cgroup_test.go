package inspector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadCgroupPaths covers which side of the agent's own cgroup namespace the
// reads happen on. The one case a test cannot reach is the one that matters in
// the DaemonSet - joining the node's namespace needs CAP_SYS_ADMIN and a real
// namespace to join - so what is pinned here is that the read always happens,
// exactly once, and that a namespace crossed or not crossed is reported as such.
func TestReadCgroupPaths(t *testing.T) {
	tests := []struct {
		name           string
		self, init     string // the ns links to lay down, empty for none
		wantNamespaced bool
		wantNote       bool
	}{
		{
			// An agent on the node: nothing between it and the paths.
			name: "the node's own namespace",
			self: "cgroup:[4026531835]", init: "cgroup:[4026531835]",
		},
		{
			// Unprivileged, so init's link cannot be read - which also means the
			// agent is reading its own /proc, where nothing is displaced.
			name: "init's link unreadable",
			self: "cgroup:[4026531835]",
		},
		{
			// A namespace of its own, and no real one to join in a fake /proc:
			// the read still happens, and the page is told the paths are the
			// agent's own view.
			name: "a namespace of its own that cannot be joined",
			self: "cgroup:[4026532451]", init: "cgroup:[4026531835]",
			wantNamespaced: true, wantNote: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.self != "" {
				writeCgroupNS(t, root, "self", tc.self)
			}
			if tc.init != "" {
				writeCgroupNS(t, root, "1", tc.init)
			}

			reads := 0
			ns := readCgroupPaths(root, func() { reads++ })
			if reads != 1 {
				t.Errorf("read ran %d times, want exactly once", reads)
			}
			if ns.Namespaced != tc.wantNamespaced {
				t.Errorf("namespaced = %v, want %v", ns.Namespaced, tc.wantNamespaced)
			}
			if (ns.Note != "") != tc.wantNote {
				t.Errorf("note %q, want one: %v", ns.Note, tc.wantNote)
			}
		})
	}
}

// TestRunInCgroupNS pins the contract the namespace crossing rests on: fn runs
// only when the namespace was actually joined. Whether it can be joined here
// depends on the privileges of the run - CAP_SYS_ADMIN in the namespace's owning
// user namespace - so both outcomes are legitimate, and the test says what each
// one has to look like rather than requiring one of them.
func TestRunInCgroupNS(t *testing.T) {
	ran := false
	err := runInCgroupNS("/proc/self/ns/cgroup", func() { ran = true })
	if err != nil && ran {
		t.Errorf("fn ran even though the namespace was not joined: %v", err)
	}
	if err == nil && !ran {
		t.Error("namespace joined but fn never ran")
	}

	// A namespace that is not there is an error, and nothing runs.
	ran = false
	if err := runInCgroupNS(filepath.Join(t.TempDir(), "nothing"), func() { ran = true }); err == nil || ran {
		t.Errorf("err %v, ran %v: want an error and nothing run", err, ran)
	}
}

// TestReadCgroupsFlagsUnresolvedPaths checks the last line of defence: a path
// that still climbs out of a namespace has to be marked as the agent's own view
// however it got there, since no cgroup on the node is named "..".
func TestReadCgroupsFlagsUnresolvedPaths(t *testing.T) {
	sample := cgroupSample{Path: "/../../../kubepods.slice/podB.slice/etcd.scope", PID: 1300, Comm: "etcd"}
	cg := readCgroups(t.TempDir(), t.TempDir(), cgroupNS{}, "/", nil, sample)

	if !cg.Namespaced || cg.NamespaceNote == "" {
		t.Errorf("cgroups %+v, want a path that climbs marked as the agent's own view", cg)
	}
}

func TestCgroupMode(t *testing.T) {
	const (
		v2 = "36 26 0:31 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate\n"
		v1 = "31 24 0:26 / /sys/fs/cgroup/memory rw,nosuid shared:10 - cgroup cgroup rw,memory\n" +
			"32 24 0:27 / /sys/fs/cgroup/pids rw,nosuid shared:11 - cgroup cgroup rw,pids\n"
		unified = "30 24 0:25 / /sys/fs/cgroup/unified rw,nosuid shared:9 - cgroup2 cgroup2 rw\n"
	)
	tests := []struct {
		name      string
		mountinfo string
		want      string
	}{
		{"unified", v2, "unified"},
		{"legacy", v1, "legacy"},
		{"hybrid", unified + v1, "hybrid"},
		{"no cgroups at all", "26 32 0:24 / /sys rw,relatime shared:7 - sysfs sysfs rw\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeMountinfo(t, root, "1", tc.mountinfo)

			mode, source := cgroupMode(root)
			if mode != tc.want {
				t.Errorf("mode %q, want %q", mode, tc.want)
			}
			if tc.want != "" && !strings.HasSuffix(source, "/1/mountinfo") {
				t.Errorf("source %q, want pid 1's mount table", source)
			}
		})
	}
}

// TestCgroupModePrefersPid1 checks the node's own mount table wins over the
// agent's: with hostPID pid 1 is the node's init, while the agent's
// /sys/fs/cgroup is whatever its runtime handed the container.
func TestCgroupModePrefersPid1(t *testing.T) {
	root := t.TempDir()
	writeMountinfo(t, root, "1", "31 24 0:26 / /sys/fs/cgroup/memory rw shared:10 - cgroup cgroup rw,memory\n")
	writeMountinfo(t, root, "self", "36 26 0:31 / /sys/fs/cgroup rw shared:9 - cgroup2 cgroup2 rw\n")

	if mode, _ := cgroupMode(root); mode != "legacy" {
		t.Errorf("mode %q, want legacy - pid 1's table is the node's", mode)
	}

	// With pid 1 unreadable the agent's own table is all there is, and it is
	// still an answer worth giving.
	own := t.TempDir()
	writeMountinfo(t, own, "self", "36 26 0:31 / /sys/fs/cgroup rw shared:9 - cgroup2 cgroup2 rw\n")
	mode, source := cgroupMode(own)
	if mode != "unified" || !strings.HasSuffix(source, "/self/mountinfo") {
		t.Errorf("mode %q from %q, want unified from the agent's own table", mode, source)
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

func TestDriverFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2eb.slice/cri-containerd-c08.scope", "systemd"},
		{"/kubepods/burstable/pod2ebef25f/c0831e9267e2", "cgroupfs"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := driverFromPath(tc.path); got != tc.want {
			t.Errorf("driverFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestCgroupDriverFromKubelet covers the three things that can settle the
// driver, in the order they are asked.
func TestCgroupDriverFromKubelet(t *testing.T) {
	systemdPod := cgroupSample{Path: "/kubepods.slice/kubepods-pod9f.slice/cri-containerd-77.scope", PID: 1300, Comm: "nginx"}
	cgroupfsPod := cgroupSample{Path: "/kubepods/burstable/pod9f/77", PID: 1300, Comm: "nginx"}
	kubelet := Component{Name: "kubelet", PID: 900, Cmdline: "/usr/bin/kubelet --cgroup-driver=systemd"}

	t.Run("flag", func(t *testing.T) {
		driver, source := cgroupDriver(t.TempDir(), t.TempDir(), []Component{kubelet}, systemdPod)
		if driver != "systemd" {
			t.Errorf("driver %q, want systemd", driver)
		}
		if !strings.Contains(source, "--cgroup-driver on kubelet(900)") {
			t.Errorf("source %q, want the flag it was read from", source)
		}
	})

	t.Run("config file through the kubelet's own root", func(t *testing.T) {
		procRoot := t.TempDir()
		configDir := filepath.Join(procRoot, "900", "root", "var", "lib", "kubelet")
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			t.Fatal(err)
		}
		config := "apiVersion: kubelet.config.k8s.io/v1beta1\ncgroupDriver: systemd\nkind: KubeletConfiguration\n"
		if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}

		plain := Component{Name: "kubelet", PID: 900, Cmdline: "/usr/bin/kubelet --config=/var/lib/kubelet/config.yaml"}
		driver, source := cgroupDriver(procRoot, t.TempDir(), []Component{plain}, systemdPod)
		if driver != "systemd" {
			t.Errorf("driver %q, want systemd", driver)
		}
		if !strings.Contains(source, "cgroupDriver in") || !strings.Contains(source, "/900/root/var/lib/kubelet/config.yaml") {
			t.Errorf("source %q, want the config file it was read from", source)
		}
	})

	t.Run("inferred with no kubelet", func(t *testing.T) {
		driver, source := cgroupDriver(t.TempDir(), t.TempDir(), nil, cgroupfsPod)
		if driver != "cgroupfs" {
			t.Errorf("driver %q, want cgroupfs", driver)
		}
		if !strings.Contains(source, "pod cgroup path") {
			t.Errorf("source %q, want the path it was inferred from", source)
		}
	})

	// A driver changed in the config but not yet restarted into leaves the paths
	// right and the file wrong, so the setting is reported with what contradicts
	// it rather than on its own.
	t.Run("setting the paths disagree with", func(t *testing.T) {
		driver, source := cgroupDriver(t.TempDir(), t.TempDir(), []Component{kubelet}, cgroupfsPod)
		if driver != "systemd" {
			t.Errorf("driver %q, want the configured systemd", driver)
		}
		if !strings.Contains(source, "reads as cgroupfs") {
			t.Errorf("source %q, want the disagreement said out loud", source)
		}
	})

	t.Run("nothing to go on", func(t *testing.T) {
		driver, source := cgroupDriver(t.TempDir(), t.TempDir(), nil, cgroupSample{})
		if driver != "" || source != "" {
			t.Errorf("driver %q from %q, want neither - nothing on the node said", driver, source)
		}
	})
}

func TestFlagValue(t *testing.T) {
	tests := []struct {
		name    string
		cmdline string
		flag    string
		want    string
	}{
		{"joined", "kubelet --cgroup-driver=systemd --v=2", "--cgroup-driver", "systemd"},
		{"separated", "kubelet --cgroup-driver cgroupfs", "--cgroup-driver", "cgroupfs"},
		{"absent", "kubelet --v=2", "--cgroup-driver", ""},
		{"last with no value", "kubelet --cgroup-driver", "--cgroup-driver", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := flagValue(tc.cmdline, tc.flag); got != tc.want {
				t.Errorf("flagValue(%q, %q) = %q, want %q", tc.cmdline, tc.flag, got, tc.want)
			}
		})
	}
}

// TestTopLevelYAMLValue checks the line read cannot be answered by a nested key
// of the same name, which is the one way reading YAML this way could lie.
func TestTopLevelYAMLValue(t *testing.T) {
	config := `apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
someSection:
  cgroupDriver: cgroupfs
cgroupDriver: systemd # what the kubelet actually uses
`
	if got := topLevelYAMLValue([]byte(config), "cgroupDriver"); got != "systemd" {
		t.Errorf("cgroupDriver = %q, want systemd from the top level", got)
	}
	if got := topLevelYAMLValue([]byte(config), "cgroupRoot"); got != "" {
		t.Errorf("cgroupRoot = %q, want nothing - it is not in the file", got)
	}
}

// writeCgroupNS lays out a /proc/<pid>/ns/cgroup link, the way the kernel names
// one: "cgroup:[4026531835]".
func writeCgroupNS(t *testing.T, root, pid, link string) {
	t.Helper()
	dir := filepath.Join(root, pid, "ns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(link, filepath.Join(dir, "cgroup")); err != nil {
		t.Fatal(err)
	}
}
