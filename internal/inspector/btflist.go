package inspector

// Listing the BTF objects loaded in the kernel, the way `bpftool btf show`
// does. This is separate from btf.go, which decodes map keys and values with a
// map's BTF - that file is a formatter, this one is an enumerator.

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// The kinds of BTF a node carries. The kernel only distinguishes its own BTF
// from userspace's (bpf_btf_info.kernel_btf); splitting the kernel's in two is
// this UI's doing, because vmlinux is one object and the modules are a hundred.
const (
	BTFKindVmlinux = "vmlinux"
	BTFKindModule  = "module"
	BTFKindUser    = "user"
)

// BTFSummary is one BTF object, as the btf list shows it. There is deliberately
// no program or map list here: both objects carry their own btf_id, and the UI
// joins them - which is also how it reaches the loaders behind those programs,
// something a per-BTF listing cannot see.
type BTFSummary struct {
	ID   uint32
	Name string // empty for anonymous BTF, which most program BTF is
	Kind string
	Size uint32 // raw BTF bytes
	PIDs []ProcessRef
}

// bpfBTFInfo mirrors the kernel's struct bpf_btf_info. cilium/ebpf reads all of
// this into btf.HandleInfo but keeps the size unexported, and the size is the
// one number that says what a BTF object costs - so we query it ourselves, the
// same way btf.go's queryMapInfo does for the key/value type ids.
type bpfBTFInfo struct {
	BTF       uint64
	BTFSize   uint32
	ID        uint32
	Name      uint64
	NameLen   uint32
	KernelBTF uint32
}

// queryBTFSize returns the raw size in bytes of the BTF object behind fd. The
// name and id are left to btf.HandleInfo, which already does the two-call dance
// a variable-length name needs; this asks only for the fixed-size fields, so
// the nil Name pointer and zero BTFSize are what we want - a non-zero BTFSize
// would ask the kernel to copy the whole blob (megabytes, for vmlinux).
func queryBTFSize(fd int) (uint32, error) {
	var info bpfBTFInfo
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
		return 0, errno
	}
	return info.BTFSize, nil
}

// ListBTF returns every BTF object loaded in the kernel, including the
// processes holding an open fd to each (resolved from /proc). It mirrors
// `bpftool btf show`.
//
// Expect most rows to be the kernel's own: vmlinux plus one per module with BTF,
// which on an ordinary node is a hundred or more. Those are the node's, not any
// program's, and nothing cross-references them - the UI files them separately
// for that reason.
func (i *Inspector) ListBTF() ([]BTFSummary, error) {
	// Scan /proc once up front, as ListMaps and ListPrograms do: a scan failure
	// (e.g. no hostPID) just yields no PIDs; it never fails the listing.
	pidsByBTF := scanBTFPIDs("/proc")

	var out []BTFSummary
	it := new(btf.HandleIterator)
	defer it.Handle.Close()

	for it.Next() {
		info, err := it.Handle.Info()
		if err != nil {
			// Race: the BTF may have gone away between IDs. Skip it, as the
			// map and program loops do.
			continue
		}
		// A size we could not read is reported as zero rather than dropping the
		// row: the id, name and kind are the answer, and the size is a detail.
		size, _ := queryBTFSize(it.Handle.FD())
		out = append(out, BTFSummary{
			ID:   uint32(info.ID),
			Name: info.Name,
			Kind: btfKind(info),
			Size: size,
			PIDs: pidsByBTF[uint32(info.ID)],
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate BTF: %w", err)
	}
	return out, nil
}

func btfKind(info *btf.HandleInfo) string {
	switch {
	case info.IsVmlinux():
		return BTFKindVmlinux
	case info.IsModule():
		return BTFKindModule
	default:
		return BTFKindUser
	}
}
