package inspector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The readlink targets of an fd pointing at a BPF object
// (e.g. /proc/<pid>/fd/7 -> "anon_inode:bpf-prog"), and the fdinfo key naming
// the object's id, per kind.
const (
	bpfProgLinkPrefix = "anon_inode:bpf-prog"
	bpfProgIDKey      = "prog_id:"
	bpfMapLinkPrefix  = "anon_inode:bpf-map"
	bpfMapIDKey       = "map_id:"
	// A BTF fd is named "btf" rather than "bpf-btf" - the kernel's anon inode
	// for it predates the "bpf-" prefix the other object kinds carry.
	bpfBTFLinkPrefix = "anon_inode:btf"
	bpfBTFIDKey      = "btf_id:"
)

// scanProgramPIDs returns, per program ID, the processes holding an open fd to
// that program - the same information `bpftool prog show` reports as `pids`.
func scanProgramPIDs(procRoot string) map[uint32][]ProcessRef {
	return scanObjectPIDs(procRoot, bpfProgLinkPrefix, bpfProgIDKey)
}

// scanMapPIDs returns, per map ID, the processes holding an open fd to that map
// - the same information `bpftool map show` reports as `pids`.
func scanMapPIDs(procRoot string) map[uint32][]ProcessRef {
	return scanObjectPIDs(procRoot, bpfMapLinkPrefix, bpfMapIDKey)
}

// scanBTFPIDs returns, per BTF ID, the processes holding an open fd to that BTF
// object - the same information `bpftool btf show` reports as `pids`. Expect
// this to be empty more often than for maps and programs: a loader closes the
// BTF fd once its programs are loaded, and the objects keep the BTF alive on
// their own kernel references.
func scanBTFPIDs(procRoot string) map[uint32][]ProcessRef {
	return scanObjectPIDs(procRoot, bpfBTFLinkPrefix, bpfBTFIDKey)
}

// scanObjectPIDs walks procRoot (normally /proc) and returns, per BPF object ID,
// the processes holding an open fd to that object. linkPrefix selects the kind of
// object by its anon_inode name and idKey names the fdinfo field carrying its id.
// It is best-effort: unreadable processes/fds are skipped, and any top-level
// failure yields an empty map rather than an error, so a caller without
// hostPID/privileges still lists objects, just without holders.
func scanObjectPIDs(procRoot, linkPrefix, idKey string) map[uint32][]ProcessRef {
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

		var comm string // read lazily, only when this process holds an object
		seen := map[uint32]bool{}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, linkPrefix) {
				continue
			}
			data, err := os.ReadFile(filepath.Join(procDir, "fdinfo", fd.Name()))
			if err != nil {
				continue
			}
			objID, ok := parseObjectID(data, idKey)
			if !ok || seen[objID] {
				continue // not the expected fdinfo, or this pid already counted
			}
			seen[objID] = true
			if comm == "" {
				comm = readComm(procDir)
			}
			result[objID] = append(result[objID], ProcessRef{PID: uint32(pid), Comm: comm})
		}
	}
	return result
}

// parseObjectID extracts the "<idKey>\t<n>" value from a bpf object fd's fdinfo
// (e.g. "prog_id:" for a program fd, "map_id:" for a map fd).
func parseObjectID(fdinfo []byte, idKey string) (uint32, bool) {
	for _, line := range strings.Split(string(fdinfo), "\n") {
		rest, ok := strings.CutPrefix(line, idKey)
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
