package inspector

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// linkTypeNames maps kernel BPF link types to short names. link.Type is a bare
// uint32 with no String(), so we name it ourselves (uapi/linux/bpf.h).
var linkTypeNames = map[link.Type]string{
	0: "unspec", 1: "raw_tracepoint", 2: "tracing", 3: "cgroup", 4: "iter",
	5: "netns", 6: "xdp", 7: "perf_event", 8: "kprobe_multi", 9: "struct_ops",
	10: "netfilter", 11: "tcx", 12: "uprobe_multi", 13: "netkit", 14: "sockmap",
}

func linkTypeName(t link.Type) string {
	if name, ok := linkTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("type(%d)", uint32(t))
}

// The BPF_LINK_TYPE_* values whose attach detail linkAttach formats
// (uapi/linux/bpf.h), matching their entries in linkTypeNames.
const (
	linkTypeRawTracepoint link.Type = 1
	linkTypeTracing       link.Type = 2
	linkTypeCgroup        link.Type = 3
	linkTypePerfEvent     link.Type = 7
)

// linkAttachDetail is what a link's type-specific info comes to: the one line
// the table prints, and - for a cgroup link - the path its cgroup id names,
// which the table hangs in a tooltip rather than in the line.
type linkAttachDetail struct {
	Text       string
	CgroupPath string
}

// linkAttach formats the best-effort attach detail for a link, à la the
// type-specific second line of `bpftool link show`. raw_tracepoint, tracing (the
// link type of an LSM program attached to a hook), cgroup (the link type of one
// attached to a cgroup fd instead) and perf_event are handled today; other types
// return "" (rendered as "-") until enriched.
func linkAttach(info *link.Info, res *linkResolver) linkAttachDetail {
	switch info.Type {
	case linkTypeRawTracepoint:
		return linkAttachDetail{Text: rawTracepointAttach(info)}
	case linkTypeTracing:
		return linkAttachDetail{Text: tracingAttach(info, res)}
	case linkTypeCgroup:
		return cgroupAttach(info, res)
	case linkTypePerfEvent:
		return linkAttachDetail{Text: perfEventAttach(info)}
	default:
		return linkAttachDetail{}
	}
}

// rawTracepointAttach formats the attach detail for a raw_tracepoint link: the
// tracepoint it hooks, à la bpftool's `tp 'sched_switch'`. A tp_btf program is a
// tracing link instead, not this type. Returns "" when the kernel exposes no
// name.
func rawTracepointAttach(info *link.Info) string {
	rt := info.RawTracepoint()
	if rt == nil || rt.Name == "" {
		return ""
	}
	return fmt.Sprintf("tp '%s'", rt.Name)
}

// perfEventSubNames maps sys.PerfEventType values to short names. The sys package
// is internal, so we match on the uint32 value (uapi/linux/bpf.h bpf_perf_event_type).
var perfEventSubNames = map[uint32]string{
	1: "uprobe", 2: "uretprobe", 3: "kprobe", 4: "kretprobe", 5: "tracepoint", 6: "event",
}

// perfEventAttach formats the attach detail for a perf_event link, à la the
// second line of `bpftool link show` for a perf_event: the probe sub-type and,
// for k(ret)probes, the target address, resolved function symbol (with offset),
// and missed count the kernel exposes. The kernel resolves the address to its
// kallsyms symbol for us (KprobeInfo.Function, since cilium/ebpf v0.21). Returns
// "" when the kernel exposes no perf_event detail.
func perfEventAttach(info *link.Info) string {
	pe := info.PerfEvent()
	if pe == nil {
		return ""
	}
	sub, ok := perfEventSubNames[uint32(pe.Type)]
	if !ok {
		sub = fmt.Sprintf("perf(%d)", uint32(pe.Type))
	}
	if kp := pe.Kprobe(); kp != nil {
		if kp.Address != 0 {
			sub += fmt.Sprintf(" %x", kp.Address)
		}
		if kp.Function != "" {
			sub += " " + kp.Function
			if kp.Offset > 0 {
				sub += fmt.Sprintf("+0x%x", kp.Offset)
			}
		}
		if kp.Missed > 0 {
			sub += fmt.Sprintf(" missed=%d", kp.Missed)
		}
	}
	if tp := pe.Tracepoint(); tp != nil && tp.Tracepoint != "" {
		sub += " " + tp.Tracepoint
	}
	if up := pe.Uprobe(); up != nil && up.File != "" {
		sub += fmt.Sprintf(" %s+0x%x", up.File, up.Offset)
	}
	return sub
}

// tracingProgTypeNames maps the program types that can hold a tracing link to
// their bpftool names (prog_type_name[] in libbpf.c).
var tracingProgTypeNames = map[ebpf.ProgramType]string{
	ebpf.Tracing: "tracing", ebpf.Extension: "ext", ebpf.LSM: "lsm",
}

func tracingProgTypeName(t ebpf.ProgramType) string {
	if name, ok := tracingProgTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("prog(%d)", uint32(t))
}

// attachTypeNames maps bpf_attach_type values to the names bpftool prints for
// them (attach_type_name[] in libbpf.c) - lsm_mac for an LSM program attached to
// a hook, lsm_cgroup for one attached to a cgroup fd, trace_fentry and friends
// for the family sharing the tracing link type, the cgroup_* set for the cgroup
// program types that predate BPF LSM. The sys package is internal, so we match
// on the uint32 value.
var attachTypeNames = map[uint32]string{
	0: "cgroup_inet_ingress", 1: "cgroup_inet_egress", 2: "cgroup_inet_sock_create",
	3: "cgroup_sock_ops", 4: "sk_skb_stream_parser", 5: "sk_skb_stream_verdict",
	6: "cgroup_device", 7: "sk_msg_verdict", 8: "cgroup_inet4_bind",
	9: "cgroup_inet6_bind", 10: "cgroup_inet4_connect", 11: "cgroup_inet6_connect",
	12: "cgroup_inet4_post_bind", 13: "cgroup_inet6_post_bind",
	14: "cgroup_udp4_sendmsg", 15: "cgroup_udp6_sendmsg", 16: "lirc_mode2",
	17: "flow_dissector", 18: "cgroup_sysctl", 19: "cgroup_udp4_recvmsg",
	20: "cgroup_udp6_recvmsg", 21: "cgroup_getsockopt", 22: "cgroup_setsockopt",
	23: "trace_raw_tp", 24: "trace_fentry", 25: "trace_fexit", 26: "modify_return",
	27: "lsm_mac", 28: "trace_iter", 29: "cgroup_inet4_getpeername",
	30: "cgroup_inet6_getpeername", 31: "cgroup_inet4_getsockname",
	32: "cgroup_inet6_getsockname", 33: "xdp_devmap", 34: "cgroup_inet_sock_release",
	35: "xdp_cpumap", 36: "sk_lookup", 37: "xdp", 38: "sk_skb_verdict",
	39: "sk_reuseport_select", 40: "sk_reuseport_select_or_migrate",
	41: "perf_event", 42: "trace_kprobe_multi", 43: "lsm_cgroup", 44: "struct_ops",
	45: "netfilter", 46: "tcx_ingress", 47: "tcx_egress", 48: "trace_uprobe_multi",
	49: "cgroup_unix_connect", 50: "cgroup_unix_sendmsg", 51: "cgroup_unix_recvmsg",
	52: "cgroup_unix_getpeername", 53: "cgroup_unix_getsockname",
	54: "netkit_primary", 55: "netkit_peer", 56: "trace_kprobe_session",
}

func attachTypeName(t uint32) string {
	if name, ok := attachTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("attach(%d)", t)
}

// tracingAttach formats the attach detail for a tracing link - the link type an
// LSM program gets - à la the second line of `bpftool link show`:
//
//	prog_type lsm  attach_type lsm_mac  target_obj_id 1  target_btf_id 30866
//
// plus the func that target_btf_id names (bpf_lsm_<hook> for LSM, the traced
// function for fentry/fexit), which bpftool leaves as a bare id. Returns "" when
// the kernel exposes no tracing detail.
func tracingAttach(info *link.Info, res *linkResolver) string {
	ti := info.Tracing()
	if ti == nil {
		return ""
	}
	var parts []string
	if name := res.progTypeName(uint32(info.Program)); name != "" {
		parts = append(parts, "prog_type "+name)
	}
	parts = append(parts, "attach_type "+attachTypeName(uint32(ti.AttachType)))
	if ti.TargetObjectId != 0 || ti.TargetBtfId != 0 {
		parts = append(parts, fmt.Sprintf("target_obj_id %d  target_btf_id %d",
			ti.TargetObjectId, ti.TargetBtfId))
	}
	if name := res.targetName(ti.TargetObjectId, uint32(ti.TargetBtfId)); name != "" {
		parts = append(parts, "target "+name)
	}
	return strings.Join(parts, "  ")
}

// cgroupAttach formats the attach detail for a cgroup link - what an LSM program
// attached to a cgroup fd gets, rather than the tracing link an LSM program
// attached to a hook gets - à la the second line of `bpftool link show`:
//
//	cgroup_id 6423  attach_type lsm_cgroup
//
// The id is the inode number of the cgroup directory the program was attached
// to, which bpftool leaves as a bare number; the path it names is resolved
// alongside it, for the tooltip. Returns the zero detail when the kernel exposes
// no cgroup info.
func cgroupAttach(info *link.Info, res *linkResolver) linkAttachDetail {
	cg := info.Cgroup()
	if cg == nil {
		return linkAttachDetail{}
	}
	return linkAttachDetail{
		Text: fmt.Sprintf("cgroup_id %d  attach_type %s",
			cg.CgroupId, attachTypeName(uint32(cg.AttachType))),
		CgroupPath: res.cgroupPath(cg.CgroupId),
	}
}

// linkResolver caches the lookups an attach detail needs beyond link.Info for
// the span of one ListLinks call, so a node with many links loads the (large)
// vmlinux BTF at most once, and only if a link has a target to name.
type linkResolver struct {
	progTypes   map[uint32]string    // prog id -> bpftool prog type name
	targetSpecs map[uint32]*btf.Spec // link target_obj_id -> its BTF, nil when not resolvable
	kernelBTF   *btf.Spec
	btfTried    bool
	cgroupPaths map[uint64]string // cgroup id -> path, nil until a cgroup link asks
	cgroupWalk  bool
}

func newLinkResolver() *linkResolver {
	return &linkResolver{
		progTypes:   map[uint32]string{},
		targetSpecs: map[uint32]*btf.Spec{},
	}
}

// progTypeName returns the bpftool-style type name of the program a link
// attaches, or "" when the program can't be read (it may have gone away, or the
// agent may lack the privilege).
func (r *linkResolver) progTypeName(id uint32) string {
	if name, ok := r.progTypes[id]; ok {
		return name
	}
	var name string
	if p, err := ebpf.NewProgramFromID(ebpf.ProgramID(id)); err == nil {
		if info, ierr := p.Info(); ierr == nil {
			name = tracingProgTypeName(info.Type)
		}
		p.Close()
	}
	r.progTypes[id] = name
	return name
}

// targetName names a tracing link's attach target from the target's own BTF.
// Returns "" when that BTF is unavailable or the id names something unexpected.
func (r *linkResolver) targetName(objID, btfID uint32) string {
	if btfID == 0 {
		return ""
	}
	spec := r.targetSpec(objID)
	if spec == nil {
		return ""
	}
	typ, err := spec.TypeByID(btf.TypeID(btfID))
	if err != nil {
		return ""
	}
	return targetTypeName(typ)
}

// targetTypeName names the BTF type a tracing link's target_btf_id points at: a
// func for LSM (bpf_lsm_<hook>), fentry/fexit and iter links, or - for a tp_btf
// link - the tracepoint behind the btf_trace_<name> typedef the kernel resolves
// it to. Returns "" for any other type.
func targetTypeName(typ btf.Type) string {
	switch t := typ.(type) {
	case *btf.Func:
		return t.Name
	case *btf.Typedef:
		if name, ok := strings.CutPrefix(t.Name, "btf_trace_"); ok {
			return name
		}
	}
	return ""
}

// targetSpec returns the BTF a tracing link's target_btf_id is an id in, keyed
// by the link's target_obj_id, or nil when it can't be had.
func (r *linkResolver) targetSpec(objID uint32) *btf.Spec {
	if spec, ok := r.targetSpecs[objID]; ok {
		return spec
	}
	spec := r.loadTargetSpec(objID)
	r.targetSpecs[objID] = spec
	return spec
}

// loadTargetSpec resolves a link's target_obj_id to the BTF object it names. The
// id says nothing about the kind of target: vmlinux BTF carries an object id of
// its own (1 on most kernels), so does a module's, and a link tracing another BPF
// program reports that program's id instead - an id in a different space, so only
// BTF the kernel owns can be resolved.
func (r *linkResolver) loadTargetSpec(objID uint32) *btf.Spec {
	if objID == 0 {
		return r.vmlinux() // no object id: a vmlinux target on an older kernel
	}
	h, err := btf.NewHandleFromID(btf.ID(objID))
	if err != nil {
		return nil
	}
	defer h.Close()

	info, err := h.Info()
	if err != nil || !info.IsKernel {
		return nil
	}
	if info.IsVmlinux() {
		// Cheaper from mmap-able /sys/kernel/btf/vmlinux than out of the handle.
		return r.vmlinux()
	}
	// A module's BTF is split from the kernel's, so it needs vmlinux as its base.
	base := r.vmlinux()
	if base == nil {
		return nil
	}
	spec, err := h.Spec(base)
	if err != nil {
		return nil
	}
	return spec
}

// cgroupPath names the cgroup a cgroup link's id points at. The hierarchy is
// walked at most once per ListLinks, and only if a cgroup link is there to need
// it - so a node with none pays nothing for this.
//
// Returns "" when the walk found no such cgroup: one that has gone away since
// the link was made, or one outside the tree the agent can see. An agent in a
// container without hostPID sees only its own subtree, and most ids in it will
// be another pod's.
func (r *linkResolver) cgroupPath(id uint64) string {
	if !r.cgroupWalk {
		r.cgroupWalk = true
		if root := cgroupV2Root("/proc"); root != "" {
			r.cgroupPaths = walkCgroupPaths(root)
		}
	}
	return r.cgroupPaths[id]
}

// vmlinux loads the kernel's own BTF once per resolver, returning nil when the
// kernel exposes none (CONFIG_DEBUG_INFO_BTF=n).
func (r *linkResolver) vmlinux() *btf.Spec {
	if !r.btfTried {
		r.btfTried = true
		r.kernelBTF, _ = btf.LoadKernelSpec()
	}
	return r.kernelBTF
}

// LinkSummary is the metadata shown for a BPF link.
type LinkSummary struct {
	ID     uint32
	Type   string
	ProgID uint32
	Attach string
	// CgroupPath is set for a cgroup link only: the path of the cgroup whose id
	// Attach names, as the node spells it ("/" for the root cgroup). Empty when
	// the hierarchy could not be walked or holds no such id - see
	// linkResolver.cgroupPath.
	CgroupPath string
}

// ListLinks enumerates BPF links and returns each link's type and the program
// it attaches. Link IDs are walked with a raw BPF_LINK_GET_NEXT_ID syscall
// (cilium/ebpf exposes NewFromID/Info but not a public ID iterator).
func (i *Inspector) ListLinks() ([]LinkSummary, error) {
	var out []LinkSummary
	res := newLinkResolver()
	var id uint32
	for {
		next, err := linkGetNextID(id)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				break
			}
			return nil, err
		}
		id = next

		l, err := link.NewFromID(link.ID(id))
		if err != nil {
			continue // link may have gone away between IDs
		}
		info, err := l.Info()
		l.Close()
		if err != nil {
			continue
		}
		attach := linkAttach(info, res)
		out = append(out, LinkSummary{
			ID:         uint32(info.ID),
			Type:       linkTypeName(info.Type),
			ProgID:     uint32(info.Program),
			Attach:     attach.Text,
			CgroupPath: attach.CgroupPath,
		})
	}
	return out, nil
}

// linkGetNextID issues BPF_LINK_GET_NEXT_ID for the given start id, returning
// the next link id (ENOENT when the walk is exhausted).
func linkGetNextID(start uint32) (uint32, error) {
	var attr struct {
		startID   uint32
		nextID    uint32
		openFlags uint32
	}
	attr.startID = start
	_, _, errno := syscall.Syscall(uintptr(unix.SYS_BPF),
		uintptr(unix.BPF_LINK_GET_NEXT_ID),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, errno
	}
	return attr.nextID, nil
}
