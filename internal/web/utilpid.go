package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// pidLookup is the pid -> process utility's model. The typed-in pid comes back
// so the form keeps it, next to what /proc said about it.
type pidLookup struct {
	PID string
	Err string

	Process *pb.DescribeProcessResponse

	// Parent is what /proc says about Process's parent, fetched alongside it:
	// a pid on its own rarely settles anything, and what launched it is the
	// next question. Nil when there is no parent to ask about, or when asking
	// failed - it is an extra, and must not cost the answer that was asked for.
	Parent *pb.DescribeProcessResponse
}

// innerPIDs renders the pids a process goes by below the agent's own pid
// namespace, as a chain: NSpid lists one number per level, outermost - the
// number this page was asked about - first, so the rest are the numbers it
// answers to further in. Empty when there is no level below, which is every
// process on a node running no containers, and on a kernel that does not report
// the line at all.
func innerPIDs(pids []uint32) string {
	if len(pids) < 2 {
		return ""
	}
	inner := make([]string, 0, len(pids)-1)
	for _, pid := range pids[1:] {
		inner = append(inner, strconv.FormatUint(uint64(pid), 10))
	}
	return strings.Join(inner, " -> ")
}

// nsHelp says what each kind of namespace isolates. A reader who works in
// containers all day does not need it, but the page is also read by someone who
// has met namespaces only as the thing containers are built from.
var nsHelp = map[string]string{
	"pid":    "the process ids it can see - inside a container it is pid 1 there, and this pid out here",
	"mnt":    "the filesystem tree it sees: a container's own root and mounts",
	"net":    "its own interfaces, addresses, routes and sockets",
	"user":   "its own uid and gid mapping - root inside, unprivileged outside",
	"uts":    "its own hostname and domain name",
	"ipc":    "its own System V IPC objects and POSIX message queues",
	"cgroup": "what it sees as the cgroup root, so its /proc cgroup path reads relative to that",
	"time":   "its own boot and monotonic clock offsets",
}

// namespaceHelp is the template's accessor. A kind with nothing to say about it
// - one a newer kernel has added - gets no tooltip rather than a wrong one.
func namespaceHelp(kind string) string { return nsHelp[kind] }

// ParentComm names Parent for the ppid link. "?" when there is no name to give,
// the same shorthand the inode holders use for a process that has none.
func (l *pidLookup) ParentComm() string {
	if !l.Parent.GetFound() || l.Parent.GetComm() == "" {
		return "?"
	}
	return l.Parent.GetComm()
}

// utilPID describes the process behind a pid - the raw number a map dump hands
// you most often. The pid is a query parameter rather than a form post, so an
// answer can be linked to or reloaded.
func (h *Handlers) utilPID(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "utils", Util: "pid"}
	data.Nodes, _ = h.nodes()

	look := &pidLookup{PID: strings.TrimSpace(r.URL.Query().Get("pid"))}
	data.PIDLookup = look

	var pid uint64
	if look.PID != "" {
		// Zero is rejected with the rest: /proc has no entry for it, so it is
		// a number that can never be described, not a process that has gone.
		n, err := strconv.ParseUint(look.PID, 10, 32)
		if err != nil || n == 0 {
			look.Err = "pid must be a positive number"
		} else {
			pid = n
		}
	}
	if pid == 0 {
		h.render(w, "utilpid", data)
		return
	}

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "utilpid", data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	// A handful of small /proc reads, the same order of work as a list call.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, err := client.DescribeProcess(ctx, &pb.DescribeProcessRequest{Pid: uint32(pid)})
	if err != nil {
		data.Err = err.Error()
		h.render(w, "utilpid", data)
		return
	}
	look.Process = resp

	// Pid 0 is the kernel's own ancestor, so only a real parent is worth a
	// second call. A failure here is dropped: the parent is a convenience, and
	// the process that was asked about has answered.
	if resp.GetFound() && resp.GetPpid() != 0 {
		if parent, perr := client.DescribeProcess(ctx, &pb.DescribeProcessRequest{Pid: resp.GetPpid()}); perr == nil {
			look.Parent = parent
		}
	}
	h.render(w, "utilpid", data)
}
