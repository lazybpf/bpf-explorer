package web

import (
	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
	"github.com/lazybpf/bpf-explorer/internal/inspector"
)

// btfRow is one row of the btf list: a BTF object and everything that points at
// it. `bpftool btf show` prints the first three of these (prog_ids, map_ids,
// pids); Loaders is the one this UI can add, because it knows which process
// loaded a program.
type btfRow struct {
	BTF   *pb.BTFInfo
	Progs []uint32 // programs whose btf_id is this object
	Maps  []uint32 // maps whose btf_id is this object

	// Loaders names the processes behind Progs, for a BTF object no process
	// holds an fd to - which is most of them, since a loader closes the BTF fd
	// once its programs are loaded. Same inference, and the same wording, as
	// mapLoaders: "comm(pid) via prog 57, 58".
	Loaders []string
}

// Kernel reports whether this is the kernel's own BTF rather than something a
// userspace loader brought in.
func (r btfRow) Kernel() bool { return r.BTF.GetKind() != inspector.BTFKindUser }

// Size renders the raw BTF size grouped in threes. A method rather than the
// comma template func directly: the proto field is a uint32 and comma takes the
// uint64 the walk counters use, which a template cannot convert between.
func (r btfRow) Size() string { return comma(uint64(r.BTF.GetSize())) }

// Referenced reports whether anything at all points at this BTF object.
func (r btfRow) Referenced() bool {
	return len(r.Progs) > 0 || len(r.Maps) > 0 || len(r.BTF.GetPids()) > 0
}

// btfRows joins BTF objects to the programs and maps carrying their btf_id, and
// splits the result the way the page shows it: loaded BTF first, then the
// kernel's own.
//
// The split is by kind, with one exception - a kernel BTF that something does
// point at stays in the first table. Nothing with a cross-reference should end
// up in the section the page collapses, whatever kind it is.
//
// Progs and Maps come out in the order the agent listed them, which is ascending
// id: it walks object ids upward.
func btfRows(btfs []*pb.BTFInfo, progs []*pb.ProgramInfo, maps []*pb.MapInfo) (loaded, kernel []btfRow) {
	progsByBTF := map[uint32][]uint32{}
	for _, p := range progs {
		if id := p.GetBtfId(); id != 0 {
			progsByBTF[id] = append(progsByBTF[id], p.GetId())
		}
	}
	mapsByBTF := map[uint32][]uint32{}
	for _, m := range maps {
		if id := m.GetBtfId(); id != 0 {
			mapsByBTF[id] = append(mapsByBTF[id], m.GetId())
		}
	}

	for _, b := range btfs {
		id := b.GetId()
		row := btfRow{BTF: b, Progs: progsByBTF[id], Maps: mapsByBTF[id]}
		// Only worth inferring when nothing holds an fd: a real holder is the
		// better answer, and the page shows one column, not two.
		if len(b.GetPids()) == 0 {
			row.Loaders = btfLoaders(progs, id)
		}
		if row.Kernel() && !row.Referenced() {
			kernel = append(kernel, row)
			continue
		}
		loaded = append(loaded, row)
	}
	return loaded, kernel
}

// btfLoaders names the loaders of the programs carrying this btf_id. It is the
// same inference mapLoaders makes for a map nothing holds, one hop from the BTF
// instead of from the map.
//
// One hop only: a BTF referenced by a map but by no program gets no loader here,
// even though the map's own row would infer one. That chain is real but it is
// two guesses deep, and the Maps column already names the map to follow.
func btfLoaders(progs []*pb.ProgramInfo, btfID uint32) []string {
	return loadersVia(progs, func(p *pb.ProgramInfo) bool { return p.GetBtfId() == btfID })
}
