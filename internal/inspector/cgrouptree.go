package inspector

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// cgroupAttachTypes are the attach types a program can be attached to a cgroup
// with - bpftool's cgroup_attach_types[], in bpf_attach_type order, which is the
// order bpftool prints a cgroup's programs in. Any other type queried against a
// cgroup fd is EINVAL, so this is the whole set there is to ask about.
var cgroupAttachTypes = []uint32{
	0, 1, 2, 3, 6, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19, 20, 21, 22,
	29, 30, 31, 32, 34, 43, 49, 50, 51, 52, 53,
}

// The BPF_PROG_QUERY flags that matter here, from the uapi header.
const (
	bpfFQueryEffective = 1 << 0 // BPF_F_QUERY_EFFECTIVE
	bpfFAllowOverride  = 1 << 0 // BPF_F_ALLOW_OVERRIDE
	bpfFAllowMulti     = 1 << 1 // BPF_F_ALLOW_MULTI
)

// maxQueriedProgs is how many program ids one query has room for - bpftool's
// own array size, far over the kernel's 64 programs per cgroup and type.
const maxQueriedProgs = 1024

// CgroupTree is `bpftool cgroup tree [ROOT] [effective]`: the cgroups under a
// root that have BPF programs attached, and those programs.
type CgroupTree struct {
	// MountPoint is where the node mounts cgroup v2, as the node spells it.
	MountPoint string
	// Root is where the walk started, as the node spells it.
	Root    string
	Cgroups []CgroupAttachments
}

// CgroupAttachments is one cgroup and the programs attached to it.
type CgroupAttachments struct {
	// Path is the cgroup's directory as the node spells it, under MountPoint -
	// what bpftool prints, and what a person on the node would cd into.
	Path string
	// ID is the cgroup id: the directory's inode, which a cgroup link names.
	ID       uint64
	Programs []CgroupProgram
}

// CgroupProgram is one program attached to a cgroup, as a row of bpftool's
// ID / AttachType / AttachFlags / Name table.
type CgroupProgram struct {
	ID         uint32
	AttachType string
	// AttachFlags is "multi", "override", "" for neither, or "unknown(<hex>)".
	// Empty throughout for an effective query, which the kernel answers with
	// no flags: bpftool drops the column there.
	AttachFlags string
	Name        string
	// AttachBTFName is the kernel function an lsm_cgroup program hooks
	// (bpf_lsm_socket_bind, ...). Where it cannot be named, the ids it would be
	// named from are set instead, and bpftool prints those.
	AttachBTFName  string
	AttachBTFObjID uint32
	AttachBTFID    uint32
}

// CgroupTree walks the cgroup v2 hierarchy from root and lists the programs
// attached to each cgroup, skipping the cgroups that have none - with effective,
// the programs that apply to each cgroup, inherited ones included, which is
// most cgroups on a node that attaches anything near the top.
//
// root is a path as the node spells it (/sys/fs/cgroup/kubepods.slice) or as
// /proc/<pid>/cgroup does, relative to the hierarchy (/kubepods.slice); empty
// is the whole hierarchy. Querying needs CAP_NET_ADMIN, and a query that fails
// for any reason but EINVAL fails the tree, with bpftool's message.
func (i *Inspector) CgroupTree(root string, effective bool) (*CgroupTree, error) {
	reach, point := cgroupV2Mount("/proc")
	if reach == "" {
		return nil, errors.New("cgroup v2 isn't mounted")
	}
	rel, err := cgroupTreeRoot(point, root)
	if err != nil {
		return nil, err
	}
	tree := &CgroupTree{MountPoint: point, Root: filepath.Join(point, rel)}
	start := filepath.Join(reach, rel)
	if _, err := os.Stat(start); err != nil {
		return nil, fmt.Errorf("can't iterate over %s: %w", tree.Root, err)
	}

	q := newCgroupQuerier(effective)
	err = eachCgroup(start, func(sub string, id uint64) error {
		display := tree.Root + sub
		progs, err := q.query(start+sub, display)
		if err != nil || len(progs) == 0 {
			return err
		}
		tree.Cgroups = append(tree.Cgroups, CgroupAttachments{Path: display, ID: id, Programs: progs})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tree, nil
}

// cgroupTreeRoot turns the root a person asked for into a path relative to the
// hierarchy's root: "" for the root cgroup, "/kubepods.slice" below it. Both
// spellings a node uses are accepted - under the mount point, and relative to it
// as /proc/<pid>/cgroup has it. Cleaning an absolute path cannot climb above
// "/", so the result never leaves the hierarchy.
func cgroupTreeRoot(point, root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", nil
	}
	if !path.IsAbs(root) {
		return "", fmt.Errorf("cgroup root must be an absolute path, e.g. %s/kubepods.slice", point)
	}
	root = path.Clean(root)
	if rel, ok := strings.CutPrefix(root, point); ok && (rel == "" || rel[0] == '/') {
		return rel, nil
	}
	if root == "/" {
		return "", nil
	}
	return root, nil
}

// cgroupQuerier asks one cgroup at a time which programs are attached to it,
// reusing its id buffers and remembering each program it has described, since
// an effective tree names the same few programs at every cgroup.
type cgroupQuerier struct {
	effective bool
	ids       []uint32
	flags     []uint32
	progs     map[uint32]progDesc
	res       *linkResolver // names an lsm_cgroup program's hook, from vmlinux BTF
}

type progDesc struct {
	name           string
	attachBTFName  string
	attachBTFObjID uint32
	attachBTFID    uint32
}

func newCgroupQuerier(effective bool) *cgroupQuerier {
	return &cgroupQuerier{
		effective: effective,
		ids:       make([]uint32, maxQueriedProgs),
		flags:     make([]uint32, maxQueriedProgs),
		progs:     map[uint32]progDesc{},
		res:       newLinkResolver(),
	}
}

// query lists the programs attached to the cgroup at dir, for every cgroup
// attach type in turn. display is dir as the node spells it, for the error.
func (q *cgroupQuerier) query(dir, display string) ([]CgroupProgram, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil // removed since the walk listed it
		}
		return nil, fmt.Errorf("can't open cgroup %s: %w", display, err)
	}
	defer unix.Close(fd)

	var out []CgroupProgram
	for _, typ := range cgroupAttachTypes {
		n, err := q.queryType(fd, typ)
		if errors.Is(err, unix.EINVAL) {
			continue // a type this kernel does not have
		}
		if err != nil {
			return nil, fmt.Errorf("can't query bpf programs attached to %s: %w", display, err)
		}
		for k := range n {
			out = append(out, q.program(q.ids[k], typ, q.flags[k]))
		}
	}
	return out, nil
}

// progQueryAttr is the query member of union bpf_attr, as of the kernel that
// added link ids (6.6); an older kernel reads the leading part it knows.
type progQueryAttr struct {
	targetFD        uint32
	attachType      uint32
	queryFlags      uint32
	attachFlags     uint32
	progIDs         uint64
	progCnt         uint32
	_               uint32
	progAttachFlags uint64
	linkIDs         uint64
	linkAttachFlags uint64
	revision        uint64
}

// queryType fills q.ids and q.flags with the programs attached to the cgroup fd
// with one attach type, returning how many there are. cilium/ebpf's
// link.QueryPrograms would do but for the flags, which it drops and bpftool
// prints.
//
// Each program's own flags (prog_attach_flags) are asked for on a plain query,
// as bpftool does - a kernel before 6.0 has no such field and rejects the query
// with it, so it is asked again without, and every program then gets the flags
// the cgroup was attached with. An effective query cannot be asked for flags.
func (q *cgroupQuerier) queryType(fd int, typ uint32) (int, error) {
	withFlags := !q.effective
	for {
		attr := progQueryAttr{
			targetFD:   uint32(fd),
			attachType: typ,
			progIDs:    uint64(uintptr(unsafe.Pointer(&q.ids[0]))),
			progCnt:    uint32(len(q.ids)),
		}
		if q.effective {
			attr.queryFlags = bpfFQueryEffective
		}
		if withFlags {
			clear(q.flags)
			attr.progAttachFlags = uint64(uintptr(unsafe.Pointer(&q.flags[0])))
		}
		_, _, errno := syscall.Syscall(uintptr(unix.SYS_BPF),
			uintptr(unix.BPF_PROG_QUERY),
			uintptr(unsafe.Pointer(&attr)),
			unsafe.Sizeof(attr))
		runtime.KeepAlive(q.ids)
		runtime.KeepAlive(q.flags)
		if withFlags && (errno == unix.EINVAL || errno == unix.E2BIG) {
			withFlags = false
			continue
		}
		if errno != 0 {
			return 0, errno
		}
		n := min(int(attr.progCnt), len(q.ids))
		for k := range n {
			if !withFlags || q.flags[k] == 0 {
				q.flags[k] = attr.attachFlags
			}
		}
		return n, nil
	}
}

// program describes one attached program as a row of the tree.
func (q *cgroupQuerier) program(id, typ, flags uint32) CgroupProgram {
	d, ok := q.progs[id]
	if !ok {
		d = q.describe(id)
		q.progs[id] = d
	}
	p := CgroupProgram{
		ID:             id,
		AttachType:     attachTypeName(typ),
		Name:           d.name,
		AttachBTFName:  d.attachBTFName,
		AttachBTFObjID: d.attachBTFObjID,
		AttachBTFID:    d.attachBTFID,
	}
	if !q.effective {
		p.AttachFlags = cgroupAttachFlags(flags)
	}
	return p
}

// cgroupAttachFlags names a program's attach flags the way bpftool does.
func cgroupAttachFlags(flags uint32) string {
	switch flags {
	case bpfFAllowMulti:
		return "multi"
	case bpfFAllowOverride:
		return "override"
	case 0:
		return ""
	}
	return fmt.Sprintf("unknown(%x)", flags)
}

// describe reads a program's name and, for an lsm_cgroup program, the hook it
// is attached at. A program gone since the query keeps its id and no name.
func (q *cgroupQuerier) describe(id uint32) progDesc {
	var d progDesc
	p, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		return d
	}
	defer p.Close()
	if info, err := p.Info(); err == nil {
		d.name = fullProgName(info)
	}
	if objID, btfID, err := progAttachBTF(p.FD()); err == nil && btfID != 0 {
		if name := q.res.targetName(objID, btfID); name != "" {
			d.attachBTFName = name
		} else {
			d.attachBTFObjID, d.attachBTFID = objID, btfID
		}
	}
	return d
}

// fullProgName is bpftool's get_prog_full_name: the kernel keeps 15 characters
// of a program's name, so a name that long may have been cut, and the program's
// first function in its BTF has it whole.
func fullProgName(info *ebpf.ProgramInfo) string {
	if len(info.Name) < unix.BPF_OBJ_NAME_LEN-1 {
		return info.Name
	}
	funcs, err := info.FuncInfos()
	if err != nil || len(funcs) == 0 || funcs[0].Func == nil {
		return info.Name
	}
	return funcs[0].Func.Name
}

// bpfProgInfo mirrors the kernel's struct bpf_prog_info up to attach_btf_id,
// which cilium/ebpf's ProgramInfo does not expose. The kernel fills only the
// part of it that it knows.
type bpfProgInfo struct {
	Type                 uint32
	ID                   uint32
	Tag                  [8]byte
	JitedProgLen         uint32
	XlatedProgLen        uint32
	JitedProgInsns       uint64
	XlatedProgInsns      uint64
	LoadTime             uint64
	CreatedByUID         uint32
	NrMapIDs             uint32
	MapIDs               uint64
	Name                 [16]byte
	Ifindex              uint32
	GPLCompatible        uint32
	NetnsDev             uint64
	NetnsIno             uint64
	NrJitedKsyms         uint32
	NrJitedFuncLens      uint32
	JitedKsyms           uint64
	JitedFuncLens        uint64
	BTFID                uint32
	FuncInfoRecSize      uint32
	FuncInfo             uint64
	NrFuncInfo           uint32
	NrLineInfo           uint32
	LineInfo             uint64
	JitedLineInfo        uint64
	NrJitedLineInfo      uint32
	LineInfoRecSize      uint32
	JitedLineInfoRecSize uint32
	NrProgTags           uint32
	ProgTags             uint64
	RunTimeNs            uint64
	RunCnt               uint64
	RecursionMisses      uint64
	VerifiedInsns        uint32
	AttachBTFObjID       uint32
	AttachBTFID          uint32
}

func progAttachBTF(fd int) (objID, btfID uint32, err error) {
	var info bpfProgInfo
	attr := struct {
		fd      uint32
		infoLen uint32
		info    uint64
	}{
		fd:      uint32(fd),
		infoLen: uint32(unsafe.Sizeof(info)),
		info:    uint64(uintptr(unsafe.Pointer(&info))),
	}
	_, _, errno := syscall.Syscall(uintptr(unix.SYS_BPF),
		uintptr(unix.BPF_OBJ_GET_INFO_BY_FD),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr))
	runtime.KeepAlive(&info)
	if errno != 0 {
		return 0, 0, errno
	}
	return info.AttachBTFObjID, info.AttachBTFID, nil
}
