package web

import (
	"fmt"
	"strconv"
	"time"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// bytesIEC formats a size in binary units, one decimal place: the units
// `systemctl status` and kubectl print memory in, so the two read side by side.
// Not formatMemory, which is decimal to match Tetragon's own listing.
func bytesIEC(n uint64) string {
	if n < 1024 {
		return strconv.FormatUint(n, 10) + " B"
	}
	value := float64(n)
	for _, unit := range []string{"KiB", "MiB", "GiB", "TiB"} {
		value /= 1024
		if value < 1024 || unit == "TiB" {
			return strconv.FormatFloat(value, 'f', 1, 64) + " " + unit
		}
	}
	return strconv.FormatUint(n, 10) + " B"
}

// cpuTime formats CPU time used so far, in the coarse units systemctl uses: a
// loader that has run for a day has used minutes, and the milliseconds after
// them are noise.
func cpuTime(usec uint64) string {
	d := time.Duration(usec) * time.Microsecond
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return strconv.FormatFloat(d.Seconds(), 'f', 2, 64) + "s"
	case d < time.Hour:
		return fmt.Sprintf("%dmin %ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh %dmin", int(d.Hours()), int(d.Minutes())%60)
	}
}

// cpuLimit turns cpu.max into the number of CPUs it allows, the way a pod's
// limits spell it. Empty when there is no quota.
func cpuLimit(c *pb.CgroupResources) string {
	if c.GetCpuQuotaUsec() == 0 || c.GetCpuPeriodUsec() == 0 {
		return ""
	}
	cpus := float64(c.GetCpuQuotaUsec()) / float64(c.GetCpuPeriodUsec())
	return strconv.FormatFloat(cpus, 'f', -1, 64) + " CPU"
}

// workingSet is the kubelet's working set: memory.current less the page cache
// the kernel can drop first. It is what a pod is evicted and OOM-ranked on, and
// so what kubectl top shows - lower than memory.current, which counts that
// cache too. Clamped at zero, as the kubelet does: the two files are not read
// at the same instant.
func workingSet(c *pb.CgroupResources) uint64 {
	cur, inactive := c.GetMemoryCurrentBytes(), c.GetMemoryInactiveFileBytes()
	if inactive > cur {
		return 0
	}
	return cur - inactive
}

// processCPU is a process's total CPU time, user and system together - the one
// number systemctl prints for CPU.
func processCPU(r *pb.ProcessResources) uint64 {
	return r.GetUserCpuUsec() + r.GetSystemCpuUsec()
}
