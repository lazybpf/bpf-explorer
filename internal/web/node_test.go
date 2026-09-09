package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// fullNode is a node the agent can see everything about: the case every field on
// the page has to render.
func fullNode() *pb.DescribeNodeResponse {
	return &pb.DescribeNodeResponse{
		Kernel: &pb.Kernel{
			Release: "6.12.94+deb12-arm64", Version: "#1 SMP Debian 6.12.94-1", Machine: "aarch64",
			Arch: "arm64", OsImage: "Debian GNU/Linux 12 (bookworm)", OsSource: "/proc/1/root/etc/os-release",
		},
		Cgroups: &pb.Cgroups{
			Mode: "unified", ModeSource: "/proc/1/mountinfo",
			Driver: "systemd", DriverSource: "cgroupDriver in /proc/900/root/var/lib/kubelet/config.yaml",
			AgentPath:   "/kubepods.slice/kubepods-besteffort.slice/agent.scope",
			ExamplePath: "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2eb.slice/cri-containerd-c08.scope",
			ExamplePid:  2246, ExampleComm: "pause",
		},
		Components: []*pb.Component{
			{
				Name: "containerd", Pid: 1068, Exe: "/usr/bin/containerd", Cmdline: "/usr/bin/containerd",
				Version: "v2.3.5", VersionSource: "-X github.com/containerd/containerd/v2/version.Version",
				Module: "github.com/containerd/containerd/v2", GoVersion: "go1.26.8",
			},
			{
				Name: "kubelet", Pid: 2059, Exe: "/usr/bin/kubelet",
				Cmdline: "/usr/bin/kubelet --config=/var/lib/kubelet/config.yaml",
				Note:    "not permitted to read the binary - opening another process's exe needs root",
			},
		},
	}
}

// TestNodePage covers what the tab exists for: the two cgroup facts container
// resolution turns on, said with the evidence behind each, and a runtime named
// with the version its own binary records.
func TestNodePage(t *testing.T) {
	out := renderUtil(t, "node", pageData{Node: "node-a", Tab: "node", NodeInfo: fullNode()})

	for _, want := range []string{
		"6.12.94&#43;deb12-arm64",
		"aarch64",
		"agent built for arm64",
		"Debian GNU/Linux 12 (bookworm)",
		"/proc/1/root/etc/os-release",
		// The mode, what it means for a cgroup id, and the table it was read from.
		"unified",
		"bpf_get_current_cgroup_id() answers from",
		"/proc/1/mountinfo",
		// The driver, and what settled it rather than the bare word.
		"systemd",
		"cgroupDriver in /proc/900/root/var/lib/kubelet/config.yaml",
		"cri-containerd-c08.scope",
		"v2.3.5",
		"github.com/containerd/containerd/v2",
		"built with go1.26.8",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the page to contain %q\n%s", want, out)
		}
	}

	// Both the example pod's process and each component link on to the pid page,
	// which is where the number becomes a process.
	for _, want := range []string{
		`href="/nodes/node-a/utils/pid?pid=2246"`,
		`href="/nodes/node-a/utils/pid?pid=1068"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q to link on to the pid page\n%s", want, out)
		}
	}

	// A component whose binary could not be read is listed with the reason in
	// place of a version, never as if it had none.
	if !strings.Contains(out, "opening another process&#39;s exe needs root") {
		t.Errorf("expected the unread binary's note on the page\n%s", out)
	}
}

// TestNodePageCgroupNamespace covers the three things the page can be looking
// at: paths read straight, paths read from the node's namespace because the
// agent is in one of its own, and paths it could not read from there at all -
// where what is shown is the agent's own view and has to say so.
func TestNodePageCgroupNamespace(t *testing.T) {
	// An agent on the node resolved nothing, and must not say it did.
	plain := renderUtil(t, "node", pageData{Node: "node-a", Tab: "node", NodeInfo: fullNode()})
	if strings.Contains(plain, "cgroup namespace of its own") {
		t.Errorf("page claimed a namespace it never had to cross\n%s", plain)
	}

	joined := fullNode()
	joined.Cgroups.Namespaced = true
	out := renderUtil(t, "node", pageData{Node: "node-a", Tab: "node", NodeInfo: joined})
	for _, want := range []string{"cgroup namespace of its own", "read from the node's own namespace"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the page to contain %q\n%s", want, out)
		}
	}
	if strings.Contains(out, `class="warn"`) {
		t.Errorf("a namespace that was crossed is not a warning\n%s", out)
	}

	// The paths are the agent's own view: that is a warning, since every one of
	// them then reads as a path the node does not have.
	stuck := fullNode()
	stuck.Cgroups.Namespaced = true
	stuck.Cgroups.NamespaceNote = "the node's cgroup namespace could not be entered (operation not permitted)"
	out = renderUtil(t, "node", pageData{Node: "node-a", Tab: "node", NodeInfo: stuck})
	if !strings.Contains(out, "could not be entered") || !strings.Contains(out, `class="warn"`) {
		t.Errorf("expected a warning that the paths are the agent's own\n%s", out)
	}
}

// TestNodePageUnseen checks a node the agent can barely see says so in each
// place, rather than leaving a blank that reads as a fact.
func TestNodePageUnseen(t *testing.T) {
	out := renderUtil(t, "node", pageData{
		Node: "node-a", Tab: "node",
		NodeInfo: &pb.DescribeNodeResponse{Kernel: &pb.Kernel{Release: "6.1.0"}, Cgroups: &pb.Cgroups{}},
	})

	for _, want := range []string{
		"os-release is on the node's root",
		"no cgroup mounts found",
		"nothing on the node said",
		"no <code>kubepods</code> cgroup found",
		// No runtime at all is the one that names its likeliest cause.
		"the agent cannot see host pids",
		"<code>hostPID</code>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the page to explain %q\n%s", want, out)
		}
	}
}

// TestNodePageError checks a node whose agent could not be reached renders the
// error and nothing that claims to describe the node.
func TestNodePageError(t *testing.T) {
	out := renderUtil(t, "node", pageData{Node: "node-a", Tab: "node", Err: "no agent for node node-a"})
	if !strings.Contains(out, "no agent for node node-a") {
		t.Errorf("expected the dial error on the page\n%s", out)
	}
	if strings.Contains(out, "container runtime") {
		t.Errorf("expected no node facts without an answer to base them on\n%s", out)
	}
}

// TestNodeTabIsActive keeps the node tab marked as the page you are on - it is
// the first entry in the bar, so an unmarked one would read as the maps tab
// being the default.
func TestNodeTabIsActive(t *testing.T) {
	out := renderUtil(t, "node", pageData{Node: "node-a", Tab: "node", NodeInfo: fullNode()})
	if !strings.Contains(out, `<a class="active" href="/nodes/node-a/node">node</a>`) {
		t.Errorf("expected the node tab to be marked active\n%s", out)
	}
}

// TestNodePickerLandsOnTheNodeTab covers the index, where nothing is selected:
// each node button opens that node's own page, named as the node itself rather
// than as a view of something on it.
func TestNodePickerLandsOnTheNodeTab(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.render(rec, "index", pageData{Tab: "node", Nodes: []string{"node-a", "node-b"}})

	out := rec.Body.String()
	if !strings.Contains(out, `href="/nodes/node-a/node" title="node-a itself: kernel, cgroups, container runtime"`) {
		t.Errorf("expected the picker to open node-a's own page\n%s", out)
	}
}

func TestNodeLinkTitle(t *testing.T) {
	tests := []struct {
		tab  string
		want string
	}{
		{"node", "node-a itself: kernel, cgroups, container runtime"},
		{"maps", "maps on node-a"},
		{"utils", "utils on node-a"},
	}
	for _, tc := range tests {
		if got := nodeLinkTitle(tc.tab, "node-a"); got != tc.want {
			t.Errorf("nodeLinkTitle(%q, node-a) = %q, want %q", tc.tab, got, tc.want)
		}
	}
}

func TestNodePageTitle(t *testing.T) {
	if got := pageTitle("node", pageData{Node: "node-a"}); got != "node - node-a - bpf-explorer" {
		t.Errorf("pageTitle = %q, want %q", got, "node - node-a - bpf-explorer")
	}
}

func TestCgroupHelp(t *testing.T) {
	for _, mode := range []string{"unified", "legacy", "hybrid"} {
		if cgroupHelp(mode) == "" {
			t.Errorf("no gloss for cgroup mode %q", mode)
		}
	}
	// A mode this build does not know gets no gloss rather than a wrong one.
	if got := cgroupHelp("something-new"); got != "" {
		t.Errorf("cgroupHelp(%q) = %q, want nothing", "something-new", got)
	}
}
