package inspector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReadCPUTimes covers a comm that would throw off a split from the start:
// it holds both a space and a closing parenthesis.
func TestReadCPUTimes(t *testing.T) {
	dir := t.TempDir()
	stat := "42 (a) b) R 1 42 42 0 -1 4194560 100 0 0 0 1234 56 0 0 20 0 1 0 100 0 0\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	user, system := readCPUTimes(dir)
	if user != 12340*time.Millisecond || system != 560*time.Millisecond {
		t.Errorf("readCPUTimes = %v, %v; want 12.34s, 560ms", user, system)
	}

	if user, system := readCPUTimes(t.TempDir()); user != 0 || system != 0 {
		t.Errorf("missing stat read as %v, %v", user, system)
	}
}

func TestReadCgroupDir(t *testing.T) {
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"memory.current": "104857600\n",
		"memory.peak":    "209715200\n",
		"memory.max":     "max\n",
		"memory.stat":    "anon 1000\nfile 5000\ninactive_file 4000\n",
		"cpu.stat":       "usage_usec 3000000\nuser_usec 2000000\nsystem_usec 1000000\nnr_periods 10\nnr_throttled 3\nthrottled_usec 450000\n",
		"cpu.max":        "50000 100000\n",
		"pids.current":   "7\n",
		"pids.max":       "4096\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := readCgroupDir(dir)
	want := CgroupResources{
		MemoryCurrent: 104857600, MemoryPeak: 209715200, MemoryInactiveFile: 4000,
		CPUUsage: 3 * time.Second, CPUUser: 2 * time.Second, CPUSystem: time.Second,
		CPUQuota: 50 * time.Millisecond, CPUPeriod: 100 * time.Millisecond,
		NrThrottled: 3, CPUThrottled: 450 * time.Millisecond,
		Tasks: 7, TasksMax: 4096,
	}
	if got != want {
		t.Errorf("readCgroupDir =\n%+v\nwant\n%+v", got, want)
	}

	// No quota is "max", and reads as no limit rather than as nothing.
	if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("max 100000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readCgroupDir(dir); got.CPUQuota != 0 || got.CPUPeriod != 100*time.Millisecond {
		t.Errorf("cpu.max max = quota %v period %v", got.CPUQuota, got.CPUPeriod)
	}
}

// TestCgroupResourcesNotes checks every case where no cgroup is read says why,
// rather than coming back as a cgroup that uses nothing.
func TestCgroupResourcesNotes(t *testing.T) {
	root := t.TempDir()
	cgroupfs := t.TempDir()
	writeMountinfo(t, root, "self", "36 26 0:31 / "+cgroupfs+" rw shared:9 - cgroup2 cgroup2 rw\n")
	noMount := t.TempDir()

	tests := []struct {
		name, procRoot, path string
		ns                   cgroupNS
		note                 string
	}{
		{"no path", root, "", cgroupNS{}, "could not be read"},
		{"displaced", root, "/a", cgroupNS{Namespaced: true, Note: "the node's cgroup namespace could not be entered"}, "could not be entered"},
		{"cgroup v1", noMount, "/a", cgroupNS{}, "no cgroup v2"},
		{"escapes", root, "/../../etc", cgroupNS{}, "outside"},
		{"gone", root, "/no/such/cgroup", cgroupNS{}, "cannot open"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cgroupResources(cgroupV2Root(tt.procRoot), tt.path, tt.ns)
			if !strings.Contains(got.Note, tt.note) {
				t.Errorf("note = %q, want it to mention %q", got.Note, tt.note)
			}
		})
	}

	// The root cgroup is its own hierarchy root, and is read, not refused.
	if got := cgroupResources(cgroupfs, "/", cgroupNS{}); got.Note != "" {
		t.Errorf("root cgroup refused: %q", got.Note)
	}
}

// TestProcessResources checks the batch read: each live pid gets its own
// numbers and its own cgroup, and a pid that is gone is left out rather than
// reported as a process using nothing.
func TestProcessResources(t *testing.T) {
	root := t.TempDir()
	cgroupfs := t.TempDir()
	writeMountinfo(t, root, "self", "36 26 0:31 / "+cgroupfs+" rw shared:9 - cgroup2 cgroup2 rw\n")
	for pid, cg := range map[string]string{"10": "/a.scope", "20": "/b.scope"} {
		dir := filepath.Join(root, pid)
		cgDir := filepath.Join(cgroupfs, cg)
		for _, d := range []string{dir, cgDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for name, contents := range map[string]string{
			filepath.Join(dir, "status"):           "Name:\tx\nVmRSS:\t   " + pid + " kB\nThreads:\t1\n",
			filepath.Join(dir, "cgroup"):           "0::" + cg + "\n",
			filepath.Join(cgDir, "memory.current"): pid + "\n",
		} {
			if err := os.WriteFile(name, []byte(contents), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	got := processResources(root, []uint32{10, 20, 30})
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (pid 30 is gone): %+v", len(got), got)
	}
	for pid, want := range map[uint32]uint64{10: 10, 20: 20} {
		r := got[pid]
		if r.RSS != want*1024 || r.Cgroup.MemoryCurrent != want || r.Threads != 1 {
			t.Errorf("pid %d = %+v, want RSS %d kB and cgroup memory %d", pid, r, want, want)
		}
	}
}
