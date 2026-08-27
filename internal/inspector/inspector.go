// Package inspector reads eBPF objects from the local kernel using cilium/ebpf.
// It is the agent-side core: listing maps/programs/links and dumping map
// contents. The map/prog iteration and the BTF value formatting are ported from
// tools/lazyebpf (lazybpf.go and btfdump.go).
//
// Everything here is read-only; there is deliberately no code path that mutates
// kernel state.
package inspector

import (
	"encoding/hex"
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
)

// maxDumpEntries caps how many entries a single DumpMap page returns so a huge
// map can't hang the caller. Ported from lazyebpf.
const maxDumpEntries = 256

// MapSummary is the metadata shown in the maps list.
type MapSummary struct {
	ID         uint32
	Name       string
	Type       string
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	Dumpable   bool
	DumpNote   string // why Dumpable is false; empty when it is true
	PIDs       []ProcessRef
}

// Entry is one key/value pair, in both raw hex and BTF-formatted forms.
type Entry struct {
	KeyHex   string
	KeyFmt   string
	ValueHex string
	ValueFmt string
}

// Dump is a (possibly truncated) page of a map's contents.
type Dump struct {
	Entries   []Entry
	Truncated bool
}

// ProcessRef is a process holding an open fd to a BPF object.
type ProcessRef struct {
	PID  uint32
	Comm string
}

// ProgramSummary is the metadata shown in the programs list.
type ProgramSummary struct {
	ID     uint32
	Name   string
	Type   string
	Tag    string
	MapIDs []uint32
	PIDs   []ProcessRef
}

// Inspector reads maps/programs/links from the host kernel.
type Inspector struct{}

func New() *Inspector { return &Inspector{} }

// ListMaps iterates every map ID and returns its metadata, including the
// processes holding a reference to each map (resolved from /proc). A map is
// reported as non-dumpable when its type does not support key iteration
// (ringbuf, perf, etc.).
func (i *Inspector) ListMaps() ([]MapSummary, error) {
	// Scan /proc once up front, as ListPrograms does: a scan failure (e.g. no
	// hostPID) just yields no PIDs; it never fails the listing.
	pidsByMap := scanMapPIDs("/proc")

	var out []MapSummary
	var id ebpf.MapID
	for {
		next, err := ebpf.MapGetNextID(id)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				break
			}
			return nil, err
		}
		id = next

		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			// Race: the map may have gone away between IDs. Skip it.
			continue
		}
		info, err := m.Info()
		if err != nil {
			m.Close()
			continue
		}
		mapID, _ := info.ID()
		note := undumpableReason(info.Type)
		out = append(out, MapSummary{
			ID:         uint32(mapID),
			Name:       info.Name,
			Type:       info.Type.String(),
			KeySize:    info.KeySize,
			ValueSize:  info.ValueSize,
			MaxEntries: info.MaxEntries,
			Flags:      info.Flags,
			Dumpable:   note == "",
			DumpNote:   note,
			PIDs:       pidsByMap[uint32(mapID)],
		})
		m.Close()
	}
	return out, nil
}

// DumpMap returns up to limit entries of the map, decoding keys/values with the
// map's BTF when available (à la `bpftool map dump`), falling back to hex.
// Pagination is a simple prefix: this v1 always dumps from the start and
// truncates; the cursor is reserved for a follow-up.
func (i *Inspector) DumpMap(id uint32, limit uint32) (*Dump, error) {
	m, err := ebpf.NewMapFromID(ebpf.MapID(id))
	if err != nil {
		return nil, err
	}
	defer m.Close()

	if limit == 0 || limit > maxDumpEntries {
		limit = maxDumpEntries
	}

	keyType, valueType := mapBTFTypes(m)

	dump := &Dump{}
	key, err := m.NextKeyBytes(nil)
	if err != nil {
		return nil, fmt.Errorf("iterate: %w", err)
	}
	for key != nil {
		if uint32(len(dump.Entries)) >= limit {
			dump.Truncated = true
			break
		}
		e := Entry{KeyHex: hex.EncodeToString(key), KeyFmt: formatBTF(keyType, key)}
		if value, lerr := m.LookupBytes(key); lerr == nil && value != nil {
			e.ValueHex = hex.EncodeToString(value)
			e.ValueFmt = formatBTF(valueType, value)
		} else if lerr != nil {
			e.ValueFmt = fmt.Sprintf("<error: %v>", lerr)
		}
		dump.Entries = append(dump.Entries, e)

		if key, err = m.NextKeyBytes(key); err != nil {
			break
		}
	}
	return dump, nil
}

// ListPrograms iterates every program ID and returns its metadata, including
// the processes holding a reference to each program (resolved from /proc).
func (i *Inspector) ListPrograms() ([]ProgramSummary, error) {
	// Scan /proc once up front so we can attach holders to each program. A scan
	// failure (e.g. no hostPID) just yields no PIDs; it never fails the listing.
	pidsByProg := scanProgramPIDs("/proc")

	var out []ProgramSummary
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				break
			}
			return nil, err
		}
		id = next

		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, err := p.Info()
		if err != nil {
			p.Close()
			continue
		}
		progID, _ := info.ID()
		mapIDs, _ := info.MapIDs()
		ids := make([]uint32, 0, len(mapIDs))
		for _, mid := range mapIDs {
			ids = append(ids, uint32(mid))
		}
		out = append(out, ProgramSummary{
			ID:     uint32(progID),
			Name:   info.Name,
			Type:   info.Type.String(),
			Tag:    info.Tag,
			MapIDs: ids,
			PIDs:   pidsByProg[uint32(progID)],
		})
		p.Close()
	}
	return out, nil
}

// ProgramDump is the translated (xlated) instruction listing of a program.
type ProgramDump struct {
	Lines     []string
	Available bool
	Note      string
}

// DumpProgram returns a program's xlated instructions as formatted lines, like
// `bpftool prog dump xlated`. When the kernel does not expose the instructions
// (insufficient privilege, bpf_jit_harden, ...) it returns Available=false with
// a Note rather than an error, so the UI can explain it.
func (i *Inspector) DumpProgram(id uint32) (*ProgramDump, error) {
	p, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		return nil, err
	}
	defer p.Close()

	info, err := p.Info()
	if err != nil {
		return nil, err
	}

	insns, err := info.Instructions()
	if err != nil {
		return &ProgramDump{Available: false, Note: err.Error()}, nil
	}

	// formatListing, not cilium's own Instructions formatter, so the output can
	// be diffed against `bpftool prog dump xlated`. It interleaves the function
	// signatures and "; <source>" line-info comments that Instructions()
	// populates from BTF - when CAP_SYS_ADMIN is available - with the
	// instructions themselves, and resolveCalls names the helpers they call.
	lines := formatListing(insns, resolveCalls(insns))
	if len(lines) == 0 {
		return &ProgramDump{Available: false, Note: "kernel exposed no instructions for this program"}, nil
	}
	return &ProgramDump{Available: true, Lines: lines}, nil
}

// undumpableReason explains why a map type does not support key iteration, or
// returns "" when it does. It is the single source of truth for both the
// Dumpable flag and the note the UI shows in its place, so the two cannot
// disagree about which types dump.
func undumpableReason(t ebpf.MapType) string {
	switch t {
	case ebpf.RingBuf, ebpf.PerfEventArray:
		return "event stream, not a keyed map: entries are consumed by a reader, so there are no keys to iterate"
	case ebpf.Queue, ebpf.Stack:
		return "queue and stack entries have no keys, so there is nothing to iterate - values come off one at a time"
	default:
		return ""
	}
}
