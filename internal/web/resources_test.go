package web

import (
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

func TestBytesIEC(t *testing.T) {
	for n, want := range map[uint64]string{
		0:          "0 B",
		1023:       "1023 B",
		1024:       "1.0 KiB",
		12_897_484: "12.3 MiB",
		1 << 30:    "1.0 GiB",
	} {
		if got := bytesIEC(n); got != want {
			t.Errorf("bytesIEC(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestCPUTime(t *testing.T) {
	for usec, want := range map[uint64]string{
		0:              "0ms",
		312_400:        "312ms",
		3_214_000:      "3.21s",
		63_214_000:     "1min 3s",
		3_723_000_000:  "1h 2min",
		90_061_000_000: "25h 1min",
	} {
		if got := cpuTime(usec); got != want {
			t.Errorf("cpuTime(%d) = %q, want %q", usec, got, want)
		}
	}
}

func TestCPULimit(t *testing.T) {
	if got := cpuLimit(&pb.CgroupResources{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000}); got != "0.5 CPU" {
		t.Errorf("half a CPU = %q", got)
	}
	if got := cpuLimit(&pb.CgroupResources{CpuPeriodUsec: 100000}); got != "" {
		t.Errorf("no quota = %q, want none", got)
	}
}

func TestWorkingSet(t *testing.T) {
	if got := workingSet(&pb.CgroupResources{MemoryCurrentBytes: 1000, MemoryInactiveFileBytes: 400}); got != 600 {
		t.Errorf("workingSet = %d, want 600", got)
	}
	// Read a moment apart, the cache can briefly outgrow the total.
	if got := workingSet(&pb.CgroupResources{MemoryCurrentBytes: 100, MemoryInactiveFileBytes: 400}); got != 0 {
		t.Errorf("workingSet = %d, want 0", got)
	}
}

func TestUtilPidResources(t *testing.T) {
	out := renderUtilPid(t, &pidLookup{
		PID: "1234",
		Process: &pb.DescribeProcessResponse{
			Found: true, Pid: 1234, Comm: "loader",
			Resources: &pb.ProcessResources{
				UserCpuUsec: 2_000_000, SystemCpuUsec: 1_000_000,
				RssBytes: 10 << 20, PeakRssBytes: 20 << 20, Threads: 4,
				Cgroup: &pb.CgroupResources{
					MemoryCurrentBytes: 100 << 20, MemoryInactiveFileBytes: 40 << 20,
					MemoryMaxBytes: 512 << 20, CpuUsageUsec: 5_000_000,
					CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, CpuNrThrottled: 3,
					Tasks: 7,
				},
			},
		},
	})
	for _, want := range []string{
		"10.0 MiB", "peak 20.0 MiB", // process memory
		"3.00s", "user 2.00s, system 1.00s", // process CPU
		"100.0 MiB", "limit 512.0 MiB", "60.0 MiB", // cgroup memory and working set
		"5.00s", "limit 0.5 CPU", "3 times", // cgroup CPU
		"no limit", // tasks
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}

	// A cgroup that could not be read says why instead of showing dashes.
	noted := renderUtilPid(t, &pidLookup{
		PID: "1234",
		Process: &pb.DescribeProcessResponse{
			Found: true, Pid: 1234,
			Resources: &pb.ProcessResources{Cgroup: &pb.CgroupResources{Note: "no cgroup v2 hierarchy is mounted on the node"}},
		},
	})
	if !strings.Contains(noted, "no cgroup v2 hierarchy") {
		t.Errorf("expected the cgroup note on the page\n%s", noted)
	}
	if strings.Contains(noted, "throttled") {
		t.Errorf("throttling shown without a CPU limit\n%s", noted)
	}
}

// TestLoadersIndexResources checks the loaders list carries each loader's
// memory and CPU, with a dash for one the agent said nothing about, and none of
// it on the no-loader row, which is not a process.
func TestLoadersIndexResources(t *testing.T) {
	data := pageData{
		Node: "node-a", Tab: "loaders",
		Loaders: []loaderSummary{
			{ID: "sg_1000", Label: "agent(1000)", PID: 1000, Resources: &pb.ProcessResources{
				RssBytes: 40 << 20, UserCpuUsec: 2_000_000, SystemCpuUsec: 1_000_000,
				Cgroup: &pb.CgroupResources{
					MemoryCurrentBytes: 100 << 20, MemoryMaxBytes: 512 << 20,
					CpuUsageUsec: 125_000_000, CpuQuotaUsec: 50000, CpuPeriodUsec: 100000,
				},
			}},
			{ID: "sg_2000", Label: "gone(2000)", PID: 2000},
			{ID: "sg_3000", Label: "v1(3000)", PID: 3000, Resources: &pb.ProcessResources{
				RssBytes: 1 << 20, Cgroup: &pb.CgroupResources{Note: "no cgroup v2 hierarchy is mounted on the node"},
			}},
		},
		NoLoader: &loaderSummary{ID: unattachedGroupID, Label: unattachedLabel, Progs: 1},
	}
	out := renderUtil(t, "loaders", data)
	for _, want := range []string{
		"40.0 MiB", "3.00s", // process
		"100.0 MiB", "/ 512.0 MiB", "2min 5s", "/ 0.5 CPU", // cgroup
		`title="no cgroup v2 hierarchy is mounted on the node"`, // why a cgroup is blank
		`href="/nodes/node-a/utils/pid?pid=1000"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the loaders list to contain %q\n%s", want, out)
		}
	}
	// Every row has the same number of cells, whatever it knows.
	for _, row := range strings.Split(out, "<tr")[2:] {
		if n := strings.Count(row, "<td"); n != 9 {
			t.Errorf("row has %d cells, want 9:\n%s", n, row)
		}
	}
}

func TestLoaderPID(t *testing.T) {
	if pid, ok := loaderPID("sg_1234"); !ok || pid != 1234 {
		t.Errorf("loaderPID(sg_1234) = %d, %v", pid, ok)
	}
	for _, id := range []string{unattachedGroupID, "1234", "sg_x"} {
		if _, ok := loaderPID(id); ok {
			t.Errorf("loaderPID(%q) took it for a loader", id)
		}
	}
}
