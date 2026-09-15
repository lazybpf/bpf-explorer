package inspector

import (
	"time"

	"golang.org/x/sys/unix"
)

// bootTime returns the wall-clock instant this node booted, the origin a
// program's load time is counted from - the kernel reports load_time as
// nanoseconds on CLOCK_BOOTTIME, never as a date. Derived the way bpftool
// derives it, realtime minus boottime, so a program dated here and the same
// program in `bpftool prog show` agree.
//
// CLOCK_BOOTTIME and not CLOCK_MONOTONIC: the two diverge by however long the
// node was suspended, and load_time is on the former.
//
// This reads the agent's own clock, which is the node's: a time namespace can
// offset boottime for the processes inside it, and the agent runs in none -
// Kubernetes does not give pods one.
func bootTime() (time.Time, bool) {
	var up unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &up); err != nil {
		return time.Time{}, false
	}
	return time.Now().Add(-(time.Duration(up.Sec)*time.Second + time.Duration(up.Nsec))), true
}
