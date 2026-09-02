package web

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
	"github.com/lazybpf/bpf-explorer/internal/inspector"
)

// btfIDs is a readable form of a row list for comparisons.
func btfIDs(rows []btfRow) []uint32 {
	out := make([]uint32, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.BTF.GetId())
	}
	return out
}

func equalIDs(a []uint32, b ...uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBTFRowsJoins covers the cross-reference the page exists for: a BTF object
// shared by two programs and their map, and one carried by a map alone.
func TestBTFRowsJoins(t *testing.T) {
	btfs := []*pb.BTFInfo{
		{Id: 1, Name: "vmlinux", Kind: inspector.BTFKindVmlinux, Size: 5843431},
		{Id: 2, Name: "xt_LOG", Kind: inspector.BTFKindModule, Size: 3438},
		{Id: 30, Kind: inspector.BTFKindUser, Size: 4021},
		{Id: 31, Kind: inspector.BTFKindUser, Size: 900},
	}
	progs := []*pb.ProgramInfo{
		{Id: 57, Name: "trace_conn", BtfId: 30, Pids: []*pb.ProcessRef{{Pid: 9912, Comm: "bpftrace"}}},
		{Id: 58, Name: "trace_close", BtfId: 30, Pids: []*pb.ProcessRef{{Pid: 9912, Comm: "bpftrace"}}},
		{Id: 59, Name: "no_btf"}, // loaded without BTF: must not join to anything
	}
	maps := []*pb.MapInfo{
		{Id: 40, Name: "counters", BtfId: 30},
		{Id: 41, Name: "orphan", BtfId: 31}, // BTF carried by a map with no program
		{Id: 42, Name: "no_btf"},
	}

	loaded, kernel := btfRows(btfs, progs, maps)

	if !equalIDs(btfIDs(loaded), 30, 31) {
		t.Errorf("loaded = %v, want [30 31]", btfIDs(loaded))
	}
	if !equalIDs(btfIDs(kernel), 1, 2) {
		t.Errorf("kernel = %v, want [1 2]", btfIDs(kernel))
	}

	if got := loaded[0].Progs; !equalIDs(got, 57, 58) {
		t.Errorf("btf 30 progs = %v, want [57 58]", got)
	}
	if got := loaded[0].Maps; !equalIDs(got, 40) {
		t.Errorf("btf 30 maps = %v, want [40]", got)
	}
	// Nothing holds an fd to it, so the loaders of its programs stand in - the
	// same wording mapLoaders uses, from the same helper.
	if got := loaded[0].Loaders; len(got) != 1 || got[0] != "bpftrace(9912) via prog 57, 58" {
		t.Errorf("btf 30 loaders = %v, want [bpftrace(9912) via prog 57, 58]", got)
	}

	// A map-only BTF gets its map but no loader: that inference is one hop too
	// far, and the Maps column already names the map to follow.
	if got := loaded[1].Maps; !equalIDs(got, 41) {
		t.Errorf("btf 31 maps = %v, want [41]", got)
	}
	if got := loaded[1].Progs; len(got) != 0 {
		t.Errorf("btf 31 progs = %v, want none", got)
	}
	if got := loaded[1].Loaders; len(got) != 0 {
		t.Errorf("btf 31 loaders = %v, want none", got)
	}
}

// TestBTFRowsHoldersWinOverInference verifies a BTF object something holds an fd
// to gets no inferred loaders: a real holder is the better answer, and the page
// shows one column, not two.
func TestBTFRowsHoldersWinOverInference(t *testing.T) {
	btfs := []*pb.BTFInfo{
		{Id: 30, Kind: inspector.BTFKindUser, Pids: []*pb.ProcessRef{{Pid: 4410, Comm: "cilium-agent"}}},
	}
	progs := []*pb.ProgramInfo{
		{Id: 57, BtfId: 30, Pids: []*pb.ProcessRef{{Pid: 9912, Comm: "bpftrace"}}},
	}

	loaded, _ := btfRows(btfs, progs, nil)
	if len(loaded) != 1 {
		t.Fatalf("loaded = %v, want one row", btfIDs(loaded))
	}
	if got := loaded[0].Loaders; len(got) != 0 {
		t.Errorf("loaders = %v, want none when a process holds an fd", got)
	}
}

// TestBTFRowsKeepsReferencedKernelBTF verifies a kernel BTF object something
// points at stays in the loaded table. Nothing with a cross-reference should end
// up in the section the page folds away.
func TestBTFRowsKeepsReferencedKernelBTF(t *testing.T) {
	btfs := []*pb.BTFInfo{
		{Id: 1, Name: "vmlinux", Kind: inspector.BTFKindVmlinux},
		{Id: 2, Name: "held", Kind: inspector.BTFKindModule, Pids: []*pb.ProcessRef{{Pid: 7, Comm: "holder"}}},
		{Id: 3, Name: "used", Kind: inspector.BTFKindModule},
	}
	progs := []*pb.ProgramInfo{{Id: 57, BtfId: 3}}

	loaded, kernel := btfRows(btfs, progs, nil)
	if !equalIDs(btfIDs(loaded), 2, 3) {
		t.Errorf("loaded = %v, want [2 3]: a referenced kernel BTF is not filed away", btfIDs(loaded))
	}
	if !equalIDs(btfIDs(kernel), 1) {
		t.Errorf("kernel = %v, want [1]", btfIDs(kernel))
	}
}

// TestBTFPageRender covers the page itself: cross-reference links, the anon
// placeholder, the grouped size, and the folded kernel section.
func TestBTFPageRender(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	btfs := []*pb.BTFInfo{
		{Id: 1, Name: "vmlinux", Kind: inspector.BTFKindVmlinux, Size: 5843431},
		{Id: 30, Kind: inspector.BTFKindUser, Size: 4021},
	}
	progs := []*pb.ProgramInfo{
		{Id: 57, Name: "trace_conn", BtfId: 30, Pids: []*pb.ProcessRef{{Pid: 9912, Comm: "bpftrace"}}},
	}
	maps := []*pb.MapInfo{{Id: 40, Name: "counters", Type: "Hash", BtfId: 30}}

	data := pageData{Node: "node-a", Tab: "btf", Programs: progs, MapsByID: mapsByID(maps)}
	data.BTFLoaded, data.BTFKernel = btfRows(btfs, progs, maps)

	var buf bytes.Buffer
	if err := h.pages["btf"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		`id="btf-30"`,                      // anchor the programs/maps BTF column targets
		`href="/nodes/node-a/programs/57"`, // prog cross-reference
		`title="trace_conn"`,               // named in a tooltip
		`href="/nodes/node-a/maps/40"`,     // map cross-reference
		`title="counters (Hash)"`,          //
		"bpftrace(9912) via prog 57",       // inferred loader, nothing holds an fd
		"&lt;anon&gt;",                     // unnamed BTF says so
		"5,843,431",                        // vmlinux size, grouped
		"<details>",                        // kernel BTF is folded away
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q\n%s", want, out)
		}
	}
	// vmlinux is unreferenced, so it belongs in the folded section - after the
	// <details> that opens it, never in the table above.
	if idx, det := strings.Index(out, "vmlinux"), strings.Index(out, "<details>"); idx < det {
		t.Errorf("unreferenced vmlinux should render inside the folded kernel section\n%s", out)
	}
}

// TestBTFReverseColumns verifies the programs and maps pages link back to a
// BTF object, and say so plainly when there is none.
func TestBTFReverseColumns(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, tc := range []struct {
		page string
		data pageData
	}{
		{"programs", pageData{Node: "node-a", Tab: "programs", Programs: []*pb.ProgramInfo{
			{Id: 57, Name: "trace_conn", BtfId: 30},
			{Id: 59, Name: "no_btf"},
		}}},
		{"maps", pageData{Node: "node-a", Tab: "maps", Maps: []*pb.MapInfo{
			{Id: 40, Name: "counters", BtfId: 30},
			{Id: 42, Name: "no_btf"},
		}}},
	} {
		t.Run(tc.page, func(t *testing.T) {
			var buf bytes.Buffer
			if err := h.pages[tc.page].ExecuteTemplate(&buf, "layout", tc.data); err != nil {
				t.Fatalf("execute: %v", err)
			}
			out := buf.String()
			if want := `href="/nodes/node-a/btf#btf-30"`; !strings.Contains(out, want) {
				t.Errorf("expected %q\n%s", want, out)
			}
			// The object without BTF must not link to btf#btf-0.
			if strings.Contains(out, "btf#btf-0") {
				t.Errorf("an object without BTF should not link to btf-0\n%s", out)
			}
		})
	}
}
