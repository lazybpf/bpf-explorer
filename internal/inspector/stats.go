package inspector

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// StatsTTL is how long the stats switch stays on before the agent turns it off
// by itself. Counting costs two clock reads per program run, which shows on
// XDP and tc at high packet rates, so a forgotten toggle must not stay on.
const StatsTTL = 10 * time.Minute

// bpfStatsLink is the readlink target of a BPF_ENABLE_STATS fd: the kernel
// makes it an anon inode named "bpf-stats".
const bpfStatsLink = "anon_inode:bpf-stats"

// StatsState is whether the kernel is counting program runs, and who turned
// that on. The kernel counts while the sysctl is 1 or any process holds a
// BPF_ENABLE_STATS fd, so each of Held, Sysctl and Holders keeps it on.
type StatsState struct {
	Held    bool
	Left    time.Duration // until the agent drops its fd; set only when Held
	Sysctl  bool
	Holders []ProcessRef // other processes holding an fd
}

// On reports whether the kernel is counting, for any of those reasons.
func (st StatsState) On() bool { return st.Held || st.Sysctl || len(st.Holders) > 0 }

// StatsSwitch turns BPF run-time stats on for StatsTTL at a time. It holds a
// BPF_ENABLE_STATS fd rather than writing the sysctl: the kernel drops the fd
// when this process exits, so the stats cannot outlive the agent.
//
// This is the one part of the package that changes kernel state.
type StatsSwitch struct {
	ttl      time.Duration
	procRoot string
	enable   func() (io.Closer, error)

	mu    sync.Mutex
	fd    io.Closer
	offAt time.Time
	// gen tells a timer whose hold was replaced, or already dropped, that the
	// fd it would close is no longer the one it armed for.
	gen   uint64
	timer *time.Timer
}

// NewStatsSwitch returns the node's stats switch, off.
func NewStatsSwitch() *StatsSwitch {
	return &StatsSwitch{
		ttl:      StatsTTL,
		procRoot: "/proc",
		enable: func() (io.Closer, error) {
			return ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
		},
	}
}

// State reports the switch and what else is keeping stats on.
func (s *StatsSwitch) State() StatsState {
	s.mu.Lock()
	st := StatsState{Held: s.fd != nil}
	if st.Held {
		st.Left = max(time.Until(s.offAt), 0)
	}
	s.mu.Unlock()

	st.Sysctl = readStatsSysctl(s.procRoot)
	st.Holders = scanStatsHolders(s.procRoot, os.Getpid())
	return st
}

// Set turns the switch on or off. On while already on starts the StatsTTL
// over. Off drops only this agent's fd: stats stay on while the sysctl or
// another process keeps them on, and State says so.
func (s *StatsSwitch) Set(on bool) (StatsState, error) {
	s.mu.Lock()
	if on {
		if s.fd == nil {
			fd, err := s.enable()
			if err != nil {
				s.mu.Unlock()
				return s.State(), err
			}
			s.fd = fd
		}
		s.arm()
	} else {
		s.drop()
	}
	s.mu.Unlock()
	return s.State(), nil
}

// arm (re)starts the countdown to dropping the fd. Called with mu held.
func (s *StatsSwitch) arm() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.gen++
	gen := s.gen
	s.offAt = time.Now().Add(s.ttl)
	s.timer = time.AfterFunc(s.ttl, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.gen == gen {
			s.drop()
		}
	})
}

// drop closes the fd, if held, and stops the countdown. Called with mu held.
func (s *StatsSwitch) drop() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.gen++
	if s.fd != nil {
		s.fd.Close()
		s.fd = nil
	}
	s.offAt = time.Time{}
}

// readStatsSysctl reports whether kernel.bpf_stats_enabled is 1. The file
// shows only what was written to it, not the fds held, and is missing before
// 5.1, which counts as off.
func readStatsSysctl(procRoot string) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, "sys/kernel/bpf_stats_enabled"))
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && n != 0
}

// scanStatsHolders returns the processes, other than self, holding a
// BPF_ENABLE_STATS fd. Best-effort like scanObjectPIDs: what cannot be read is
// skipped.
func scanStatsHolders(procRoot string, self int) []ProcessRef {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var out []ProcessRef
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		procDir := filepath.Join(procRoot, e.Name())
		fdDir := filepath.Join(procDir, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err == nil && link == bpfStatsLink {
				out = append(out, ProcessRef{PID: uint32(pid), Comm: readComm(procDir)})
				break
			}
		}
	}
	return out
}
