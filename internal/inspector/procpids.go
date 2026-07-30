package inspector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// bpfProgLinkPrefix is the readlink target of an fd pointing at a BPF program
// (e.g. /proc/<pid>/fd/7 -> "anon_inode:bpf-prog").
const bpfProgLinkPrefix = "anon_inode:bpf-prog"

// scanProgramPIDs walks procRoot (normally /proc) and returns, per program ID,
// the processes holding an open fd to that program - the same information
// `bpftool prog show` reports as `pids`. It is best-effort: unreadable
// processes/fds are skipped, and any top-level failure yields an empty map
// rather than an error, so a caller without hostPID/privileges still lists
// programs, just without holders.
func scanProgramPIDs(procRoot string) map[uint32][]ProcessRef {
	result := map[uint32][]ProcessRef{}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return result
	}

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a "/proc/<pid>" directory
		}
		procDir := filepath.Join(procRoot, e.Name())
		fdDir := filepath.Join(procDir, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process gone or not readable
		}

		var comm string // read lazily, only when this process holds a prog
		seen := map[uint32]bool{}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, bpfProgLinkPrefix) {
				continue
			}
			data, err := os.ReadFile(filepath.Join(procDir, "fdinfo", fd.Name()))
			if err != nil {
				continue
			}
			progID, ok := parseProgID(data)
			if !ok || seen[progID] {
				continue // not a prog fdinfo, or this pid already counted
			}
			seen[progID] = true
			if comm == "" {
				comm = readComm(procDir)
			}
			result[progID] = append(result[progID], ProcessRef{PID: uint32(pid), Comm: comm})
		}
	}
	return result
}

// parseProgID extracts the "prog_id:\t<n>" value from a bpf program fd's fdinfo.
func parseProgID(fdinfo []byte) (uint32, bool) {
	for _, line := range strings.Split(string(fdinfo), "\n") {
		rest, ok := strings.CutPrefix(line, "prog_id:")
		if !ok {
			continue
		}
		if id, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 32); err == nil {
			return uint32(id), true
		}
	}
	return 0, false
}

// readComm returns the process command name from /proc/<pid>/comm.
func readComm(procDir string) string {
	b, err := os.ReadFile(filepath.Join(procDir, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
