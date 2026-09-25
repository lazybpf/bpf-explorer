package web

import (
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// TestCgroupsPage checks the tree reads as bpftool prints it: each cgroup's path
// above its programs' ID / AttachType / AttachFlags / Name rows, an lsm_cgroup
// program's hook after its name, and its ids where the hook has no name.
func TestCgroupsPage(t *testing.T) {
	out := renderUtil(t, "cgroups", pageData{Node: "node-a", Tab: "cgroups", CgroupTree: &cgroupTree{
		Tree: &pb.CgroupTreeResponse{
			MountPoint: "/sys/fs/cgroup",
			Root:       "/sys/fs/cgroup",
			Cgroups: []*pb.CgroupAttachments{
				{Path: "/sys/fs/cgroup/kubepods.slice", Id: 6423, Programs: []*pb.CgroupProgram{
					{Id: 41, AttachType: "cgroup_device", AttachFlags: "multi", Name: "sd_devices"},
					{Id: 57, AttachType: "lsm_cgroup", Name: "restrict_bind", AttachBtfName: "bpf_lsm_socket_bind"},
					{Id: 58, AttachType: "lsm_cgroup", Name: "restrict_mod", AttachBtfObjId: 7, AttachBtfId: 1234},
				}},
			},
		},
	}})
	for _, want := range []string{
		"<code>/sys/fs/cgroup/kubepods.slice</code>",
		"id 6423",
		`href="/nodes/node-a/cgroups?root=%2fsys%2ffs%2fcgroup%2fkubepods.slice"`,
		`href="/nodes/node-a/programs/41" target="_blank" rel="noopener" title="sd_devices"`,
		"cgroup_device", "multi", "sd_devices",
		"bpf_lsm_socket_bind",
		"attach_btf_obj_id=7 attach_btf_id=1234",
		"AttachFlags",
		"1 cgroup,\n  3 programs under <code>/sys/fs/cgroup</code>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the page to contain %q\n%s", want, out)
		}
	}
	if !strings.Contains(out, `class="active" href="/nodes/node-a/cgroups"`) {
		t.Error("expected the tab bar to mark the cgroups tab as the page you are on")
	}
}

// TestCgroupsPageEffective drops the flags column, as bpftool does: the kernel
// reports none for an effective query.
func TestCgroupsPageEffective(t *testing.T) {
	out := renderUtil(t, "cgroups", pageData{Node: "node-a", Tab: "cgroups", CgroupTree: &cgroupTree{
		Root: "/kubepods.slice", Effective: true,
		Tree: &pb.CgroupTreeResponse{MountPoint: "/sys/fs/cgroup", Root: "/sys/fs/cgroup/kubepods.slice"},
	}})
	for _, want := range []string{"checked", `value="/kubepods.slice"`, "No cgroups under /sys/fs/cgroup/kubepods.slice have programs in effect."} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the page to contain %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "AttachFlags") {
		t.Error("an effective tree has no attach flags column")
	}
}
