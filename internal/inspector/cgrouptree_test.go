package inspector

import (
	"strings"
	"testing"
	"unsafe"
)

// TestCgroupTreeRoot checks both spellings of a root are taken - under the mount
// point as the node types it, and relative to the hierarchy as
// /proc/<pid>/cgroup has it - and that no spelling walks out of the hierarchy.
func TestCgroupTreeRoot(t *testing.T) {
	const point = "/sys/fs/cgroup"
	tests := []struct {
		root, want string
	}{
		{"", ""},
		{"/sys/fs/cgroup", ""},
		{"/sys/fs/cgroup/", ""},
		{"/sys/fs/cgroup/kubepods.slice", "/kubepods.slice"},
		{" /sys/fs/cgroup/kubepods.slice/ ", "/kubepods.slice"},
		{"/kubepods.slice", "/kubepods.slice"},
		{"/", ""},
		// Not under the mount point, only sharing a prefix with it.
		{"/sys/fs/cgroupfoo", "/sys/fs/cgroupfoo"},
		{"/sys/fs/cgroup/../../../etc", "/etc"},
	}
	for _, tc := range tests {
		got, err := cgroupTreeRoot(point, tc.root)
		if err != nil {
			t.Errorf("cgroupTreeRoot(%q): %v", tc.root, err)
			continue
		}
		if got != tc.want {
			t.Errorf("cgroupTreeRoot(%q) = %q, want %q", tc.root, got, tc.want)
		}
	}
	if _, err := cgroupTreeRoot(point, "kubepods.slice"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("a relative root: err = %v, want one asking for an absolute path", err)
	}
}

func TestCgroupAttachFlags(t *testing.T) {
	for flags, want := range map[uint32]string{0: "", 1: "override", 2: "multi", 6: "unknown(6)"} {
		if got := cgroupAttachFlags(flags); got != want {
			t.Errorf("cgroupAttachFlags(%d) = %q, want %q", flags, got, want)
		}
	}
}

// TestCgroupAttachTypes checks the queried set is the cgroup one, in enum order,
// by the names bpftool gives them.
func TestCgroupAttachTypes(t *testing.T) {
	for k, typ := range cgroupAttachTypes {
		name := attachTypeName(typ)
		if !strings.HasPrefix(name, "cgroup_") && name != "lsm_cgroup" {
			t.Errorf("attach type %d (%s) is not a cgroup attach type", typ, name)
		}
		if k > 0 && typ <= cgroupAttachTypes[k-1] {
			t.Errorf("attach type %d out of enum order", typ)
		}
	}
	if len(cgroupAttachTypes) != 29 {
		t.Errorf("%d cgroup attach types, want bpftool's 29", len(cgroupAttachTypes))
	}
}

// TestBPFStructLayouts pins the two hand-written kernel structs to the uapi
// offsets: a field one word off would read another field's value, silently.
func TestBPFStructLayouts(t *testing.T) {
	var q progQueryAttr
	for name, got := range map[string]uintptr{
		"prog_ids":          unsafe.Offsetof(q.progIDs),
		"prog_cnt":          unsafe.Offsetof(q.progCnt),
		"prog_attach_flags": unsafe.Offsetof(q.progAttachFlags),
		"revision":          unsafe.Offsetof(q.revision),
		"sizeof":            unsafe.Sizeof(q),
	} {
		want := map[string]uintptr{"prog_ids": 16, "prog_cnt": 24, "prog_attach_flags": 32, "revision": 56, "sizeof": 64}[name]
		if got != want {
			t.Errorf("bpf_attr.query %s at %d, want %d", name, got, want)
		}
	}
	var p bpfProgInfo
	for name, got := range map[string]uintptr{
		"name":              unsafe.Offsetof(p.Name),
		"btf_id":            unsafe.Offsetof(p.BTFID),
		"verified_insns":    unsafe.Offsetof(p.VerifiedInsns),
		"attach_btf_obj_id": unsafe.Offsetof(p.AttachBTFObjID),
		"attach_btf_id":     unsafe.Offsetof(p.AttachBTFID),
		"sizeof":            unsafe.Sizeof(p),
	} {
		want := map[string]uintptr{"name": 64, "btf_id": 128, "verified_insns": 216,
			"attach_btf_obj_id": 220, "attach_btf_id": 224, "sizeof": 232}[name]
		if got != want {
			t.Errorf("bpf_prog_info %s at %d, want %d", name, got, want)
		}
	}
}
