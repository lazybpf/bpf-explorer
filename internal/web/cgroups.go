package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// cgroupTree is the cgroups page's model: what was asked for, kept for the form,
// next to what the agent found.
type cgroupTree struct {
	Root      string
	Effective bool
	Tree      *pb.CgroupTreeResponse
}

// cgroups lists the cgroups that have BPF programs attached - `bpftool cgroup
// tree [CGROUP_ROOT] [effective]` - on a tab of its own rather than under utils:
// it is a view of what is attached on the node, like links, not a question about
// the node. Asked nothing, it walks the whole hierarchy,
// as bpftool does; query parameters narrow it, so a subtree can be linked to.
func (h *Handlers) cgroups(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "cgroups"}
	data.Nodes, _ = h.nodes()

	q := r.URL.Query()
	look := &cgroupTree{Root: strings.TrimSpace(q.Get("root")), Effective: q.Get("effective") != ""}
	data.CgroupTree = look

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "cgroups", data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	// A query per cgroup and attach type: a few thousand syscalls on a small
	// node, and more than a list call on a busy one.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	tree, err := client.CgroupTree(ctx, &pb.CgroupTreeRequest{Root: look.Root, Effective: look.Effective})
	if err != nil {
		data.Err = err.Error()
		h.render(w, "cgroups", data)
		return
	}
	look.Tree = tree
	h.render(w, "cgroups", data)
}

// attachedCount is the number of programs across a tree, for its heading.
func attachedCount(cgroups []*pb.CgroupAttachments) int {
	n := 0
	for _, c := range cgroups {
		n += len(c.Programs)
	}
	return n
}
