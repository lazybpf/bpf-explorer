package web

import (
	"context"
	"net/http"
	"net/url"
	"time"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// cgroupModeHelp says what each cgroup mode means for reading a container back
// out of a BPF program, which is the reason the tab shows it at all.
var cgroupModeHelp = map[string]string{
	"unified": "cgroup v2 only - the single tree bpf_get_current_cgroup_id() answers from, and the one a cgroup id can be looked up in",
	"legacy":  "cgroup v1 - a container is accounted once per controller, so a cgroup id names one controller's cgroup and not the container",
	"hybrid":  "cgroup v2 mounted beside the v1 controllers - which of the two a container is accounted by depends on the controller",
}

// cgroupHelp is the template's accessor. A mode with nothing to say about it
// gets no gloss rather than a wrong one, as namespaceHelp does.
func cgroupHelp(mode string) string { return cgroupModeHelp[mode] }

// nodeDetails shows the node's own configuration: the kernel, the cgroup layout
// its containers are accounted in, and the processes that create them. It is the
// context the object tabs are read against - a pid or a cgroup id out of a map
// only becomes a container through these - and it is the first place to look
// when resolution comes out wrong on one node and right on another.
//
// It sits under utils with the lookups, which are the same kind of thing: a
// question about the node rather than a list of what is loaded on it. It is the
// one of them that answers without being asked a number first.
func (h *Handlers) nodeDetails(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "utils", Util: "node"}
	data.Nodes, _ = h.nodes()

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "node", data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	// A /proc walk plus a handful of small reads, the same order of work as a
	// list call - except for the binaries, which are read a page at a time.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	info, err := client.DescribeNode(ctx, &pb.DescribeNodeRequest{})
	if err != nil {
		data.Err = err.Error()
		h.render(w, "node", data)
		return
	}
	data.NodeInfo = info
	h.render(w, "node", data)
}

// nodeMoved forwards the page's old top-level path. It was a tab of its own
// until it moved in beside the lookups, and that URL is in bookmarks, in
// history and in whatever anyone pasted it into.
func (h *Handlers) nodeMoved(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/nodes/"+url.PathEscape(r.PathValue("node"))+"/utils/node", http.StatusFound)
}
