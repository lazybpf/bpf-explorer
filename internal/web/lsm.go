package web

import (
	"slices"
	"strings"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// lsmWarning is what the programs page says about the LSM programs it lists
// when the node may not be running them. The kernel loads and attaches an LSM
// program whether or not the bpf LSM was enabled at boot, and only calls it
// when it was, so a loader that does not check gets no error - its policy just
// is not enforced.
type lsmWarning struct {
	Programs int    // LSM programs in the listing
	Active   string // the kernel's LSMs, comma-separated as the kernel lists them
	Note     string // why the agent could not read them: the check did not run
}

// checkLSM returns the warning for a listing's LSM programs, or nil when there
// is nothing to say: no LSM programs, bpf among the active LSMs, or an agent
// too old to send them. It counts by program type, not by link: an LSM program
// can only be attached through a link, but one that is loaded and not attached
// never runs either, so the warning holds for it too.
func checkLSM(progs []*pb.ProgramInfo, lsms []string, note string) *lsmWarning {
	n := 0
	for _, p := range progs {
		if p.GetType() == "LSM" {
			n++
		}
	}
	switch {
	case n == 0:
		return nil
	case len(lsms) == 0 && note == "":
		return nil
	case len(lsms) == 0:
		return &lsmWarning{Programs: n, Note: note}
	case slices.Contains(lsms, "bpf"):
		return nil
	}
	return &lsmWarning{Programs: n, Active: strings.Join(lsms, ",")}
}
