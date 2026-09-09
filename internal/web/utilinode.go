package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// inodeLookup is the inode -> path utility's model. The typed-in values come
// back so the form keeps them, next to what the search found.
type inodeLookup struct {
	Inode  string
	Device string
	Err    string

	// Walk records that the filesystem search was asked for, and under which
	// root, so the form and the "search the filesystem" offer stay in step.
	Walk     bool
	WalkRoot string
	Stats    *pb.WalkStats

	// Searched records that a lookup actually ran, which is what makes an empty
	// Matches meaningful. Scanned is how many processes it looked through: zero
	// means /proc was not visible to the agent, and then no answer at all can be
	// read into the emptiness.
	Searched bool
	Scanned  uint32
	Matches  []*pb.InodeMatch
}

// utilInode finds the path behind an inode number. The kernel has no
// inode-to-path call, so this searches: /proc for what processes hold open, and
// on request the filesystem itself. Query parameters rather than a form post,
// so an answer can be linked to or reloaded.
func (h *Handlers) utilInode(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "utils", Util: "inode"}
	data.Nodes, _ = h.nodes()

	q := r.URL.Query()
	look := &inodeLookup{
		Inode:    strings.TrimSpace(q.Get("inode")),
		Device:   strings.TrimSpace(q.Get("dev")),
		Walk:     q.Get("walk") != "",
		WalkRoot: strings.TrimSpace(q.Get("root")),
	}
	data.InodeLookup = look

	var inode uint64
	if look.Inode != "" {
		n, err := parseInode(look.Inode)
		switch {
		case err != nil:
			look.Err = err.Error()
		case look.Device != "" && !validDevice(look.Device):
			look.Err = `device must be "major:minor" in decimal, as the mount table prints it - e.g. 253:1`
		default:
			inode = n
		}
	}
	if inode == 0 {
		h.render(w, "utilinode", data)
		return
	}

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "utilinode", data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	// Longer than a list call: the lookup reads every process's fds and
	// mappings, which on a busy node is tens of thousands of small reads. A walk
	// gets its own budget on the agent and a client timeout above it, so partial
	// results come back with an honest "gave up" rather than a dead request.
	timeout := 30 * time.Second
	if look.Walk {
		timeout = walkSeconds*time.Second + 30*time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	resp, err := client.ResolveInode(ctx, &pb.ResolveInodeRequest{
		Inode:       inode,
		Device:      look.Device,
		Walk:        look.Walk,
		WalkRoot:    look.WalkRoot,
		WalkSeconds: walkSeconds,
	})
	if err != nil {
		data.Err = err.Error()
	} else {
		look.Searched = true
		look.Scanned = resp.GetProcessesScanned()
		look.Matches = resp.GetMatches()
		look.Stats = resp.GetWalk()
	}
	h.render(w, "utilinode", data)
}

// walkSeconds is how long the agent may spend walking a filesystem before it
// returns what it has. Long enough for a root filesystem of a few million files
// on warm cache, short enough that a browser tab is not left hanging - and a
// walk that runs out says so, which is the cue to narrow the root and retry.
const walkSeconds = 60

// maxHolders caps how many processes one path lists. A shared library is mapped
// by every process that links it - on this machine libc has ninety-nine holders -
// and a hundred-row cell buries the path it belongs to. The first few name the
// kind of thing holding it; the count carries the rest.
const maxHolders = 8

// holderList is one path's holders, trimmed to what a table cell can carry.
type holderList struct {
	Head []*pb.InodeHolder
	More int
}

// holders trims a path's holder list for display, lowest pid first (the inspector
// sorts them), so what is shown is stable across reloads.
func holders(all []*pb.InodeHolder) holderList {
	if len(all) <= maxHolders {
		return holderList{Head: all}
	}
	return holderList{Head: all[:maxHolders], More: len(all) - maxHolders}
}

// parseInode accepts an inode the way a map dump shows one: decimal, or hex with
// an 0x prefix. The base is explicit rather than inferred, so a leading zero
// cannot quietly turn a decimal number into an octal one.
func parseInode(s string) (uint64, error) {
	base, digits := 10, s
	for _, prefix := range []string{"0x", "0X"} {
		if rest, ok := strings.CutPrefix(s, prefix); ok {
			base, digits = 16, rest
			break
		}
	}
	n, err := strconv.ParseUint(digits, base, 64)
	if err != nil {
		return 0, fmt.Errorf("inode must be a number - decimal, or hex with an 0x prefix")
	}
	if n == 0 {
		return 0, fmt.Errorf("inode 0 is what /proc prints for a mapping with no file behind it, so nothing can hold it")
	}
	return n, nil
}

// validDevice reports whether s is a "major:minor" device number in decimal, the
// form /proc/<pid>/mountinfo and the match rows both use.
func validDevice(s string) bool {
	major, minor, ok := strings.Cut(s, ":")
	if !ok {
		return false
	}
	for _, part := range []string{major, minor} {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}
