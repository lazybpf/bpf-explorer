package inspector

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

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

// linkAttach formats the best-effort attach detail for a link, à la the
// type-specific second line of `bpftool link show`. Only perf_event is handled
// today; other types return "" (rendered as "-") until enriched.
func linkAttach(info *link.Info) string {
	switch info.Type {
	case linkTypePerfEvent:
		return perfEventAttach(info)
	default:
		return ""
	}
}

// linkTypePerfEvent is the BPF_LINK_TYPE_PERF_EVENT value (uapi/linux/bpf.h),
// matching the "perf_event" entry in linkTypeNames.
const linkTypePerfEvent link.Type = 7

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

// LinkSummary is the metadata shown for a BPF link.
type LinkSummary struct {
	ID     uint32
	Type   string
	ProgID uint32
	Attach string
}

// ListLinks enumerates BPF links and returns each link's type and the program
// it attaches. Link IDs are walked with a raw BPF_LINK_GET_NEXT_ID syscall
// (cilium/ebpf exposes NewFromID/Info but not a public ID iterator).
func (i *Inspector) ListLinks() ([]LinkSummary, error) {
	var out []LinkSummary
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
		out = append(out, LinkSummary{
			ID:     uint32(info.ID),
			Type:   linkTypeName(info.Type),
			ProgID: uint32(info.Program),
			Attach: linkAttach(info),
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
