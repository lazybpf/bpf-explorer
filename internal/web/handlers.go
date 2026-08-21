// Package web serves the HTML frontend and fans out read-only gRPC calls to the
// per-node agents returned by internal/discovery.
package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
	"github.com/lazybpf/bpf-explorer/internal/discovery"
	"github.com/lazybpf/bpf-explorer/internal/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Handlers wires HTTP routes to gRPC fan-out over discovered agents.
type Handlers struct {
	disc          discovery.Discoverer
	pages         map[string]*template.Template
	hiddenLoaders map[uint32]bool // loader PIDs excluded from graph grouping
}

// New parses templates and returns the HTTP handlers. hiddenLoaders lists loader
// PIDs to exclude when grouping the dependency graph (e.g. {1: true} for systemd).
func New(disc discovery.Discoverer, hiddenLoaders map[uint32]bool) (*Handlers, error) {
	funcs := template.FuncMap{
		"mapFlags": mapFlags, "progName": progName, "progLoader": progLoader,
		"mapLoaders": mapLoaders, "hexASCII": hexASCII,
		// Exposed as a func so every page gets it without threading it through
		// each handler's pageData.
		"version": version.String,
	}
	pages := map[string]*template.Template{}
	for _, name := range []string{"index", "maps", "programs", "links", "graph", "graphgroup", "tracelog"} {
		t, err := template.New(name).Funcs(funcs).ParseFS(templatesFS,
			"templates/layout.html", "templates/partials.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	return &Handlers{disc: disc, pages: pages, hiddenLoaders: hiddenLoaders}, nil
}

// Router registers the read-only routes.
func (h *Handlers) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.index)
	mux.HandleFunc("GET /nodes/{node}/maps", h.maps)
	mux.HandleFunc("GET /nodes/{node}/maps/{id}", h.maps)
	mux.HandleFunc("GET /nodes/{node}/programs", h.programs)
	mux.HandleFunc("GET /nodes/{node}/programs/{id}", h.programs)
	mux.HandleFunc("GET /nodes/{node}/links", h.links)
	mux.HandleFunc("GET /nodes/{node}/graph", h.graphIndex)
	mux.HandleFunc("GET /nodes/{node}/graph/prog/{id}", h.graphProgram)
	mux.HandleFunc("GET /nodes/{node}/graph/{group}", h.graphGroup)
	mux.HandleFunc("GET /nodes/{node}/tracelog", h.tracelog)
	mux.HandleFunc("GET /nodes/{node}/tracelog/stream", h.tracelogStream)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return mux
}

// pageData is the template model shared by all pages.
type pageData struct {
	Nodes       []string
	Node        string
	Tab         string
	Err         string
	Maps        []*pb.MapInfo
	Programs    []*pb.ProgramInfo
	Links       []*pb.LinkInfo
	MapsByID    map[uint32]*pb.MapInfo // id -> map, for program map-ref tooltips
	Dump        *dumpView
	ProgDump    *progDumpView
	Mermaid     template.HTML  // per-group dependency graph definition
	GroupLabel  string         // loader label for the per-group graph page
	GraphGroups []groupSummary // loader groups for the graph index page
}

type groupSummary struct {
	ID    string
	Label string
	Progs int
	Maps  int
	Links int
}

type dumpView struct {
	ID        uint32
	Name      string
	Entries   []*pb.MapEntry
	Truncated bool
}

type progDumpView struct {
	ID        uint32
	Name      string
	Lines     []string
	Available bool
	Note      string
}

func (h *Handlers) index(w http.ResponseWriter, _ *http.Request) {
	data := pageData{Tab: "maps"}
	nodes, _ := h.nodes()
	data.Nodes = nodes
	h.render(w, "index", data)
}

func (h *Handlers) maps(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "maps"}
	data.Nodes, _ = h.nodes()

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "maps", data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	list, err := client.ListMaps(ctx, &pb.ListMapsRequest{})
	if err != nil {
		data.Err = err.Error()
		h.render(w, "maps", data)
		return
	}
	data.Maps = list.GetMaps()

	// Best-effort programs so a map nothing holds an fd to can still name the
	// loader of a program referencing it. A failure here must not break the page.
	if progs, perr := client.ListPrograms(ctx, &pb.ListProgramsRequest{}); perr == nil {
		data.Programs = progs.GetPrograms()
	}

	if idStr := r.PathValue("id"); idStr != "" {
		id, cerr := strconv.ParseUint(idStr, 10, 32)
		if cerr != nil {
			http.Error(w, "bad map id", http.StatusBadRequest)
			return
		}
		dump, derr := client.DumpMap(ctx, &pb.DumpMapRequest{Id: uint32(id)})
		if derr != nil {
			data.Err = derr.Error()
		} else {
			data.Dump = &dumpView{
				ID:        uint32(id),
				Name:      mapName(data.Maps, uint32(id)),
				Entries:   dump.GetEntries(),
				Truncated: dump.GetTruncated(),
			}
		}
	}
	h.render(w, "maps", data)
}

func (h *Handlers) programs(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "programs"}
	data.Nodes, _ = h.nodes()

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "programs", data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	list, err := client.ListPrograms(ctx, &pb.ListProgramsRequest{})
	if err != nil {
		data.Err = err.Error()
		h.render(w, "programs", data)
		return
	}
	data.Programs = list.GetPrograms()

	// Best-effort map metadata so program map-ref links can show name/type in a
	// tooltip. A failure here must not break the programs page.
	if maps, merr := client.ListMaps(ctx, &pb.ListMapsRequest{}); merr == nil {
		byID := make(map[uint32]*pb.MapInfo, len(maps.GetMaps()))
		for _, m := range maps.GetMaps() {
			byID[m.GetId()] = m
		}
		data.MapsByID = byID
	}

	if idStr := r.PathValue("id"); idStr != "" {
		id, cerr := strconv.ParseUint(idStr, 10, 32)
		if cerr != nil {
			http.Error(w, "bad program id", http.StatusBadRequest)
			return
		}
		dump, derr := client.DumpProgram(ctx, &pb.DumpProgramRequest{Id: uint32(id)})
		if derr != nil {
			data.Err = derr.Error()
		} else {
			data.ProgDump = &progDumpView{
				ID:        uint32(id),
				Name:      progName(data.Programs, uint32(id)),
				Lines:     dump.GetLines(),
				Available: dump.GetAvailable(),
				Note:      dump.GetNote(),
			}
		}
	}
	h.render(w, "programs", data)
}

// links lists the BPF links on a node, like `bpftool link show`.
func (h *Handlers) links(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "links"}
	data.Nodes, _ = h.nodes()

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "links", data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	list, err := client.ListLinks(ctx, &pb.ListLinksRequest{})
	if err != nil {
		data.Err = err.Error()
		h.render(w, "links", data)
		return
	}
	data.Links = list.GetLinks()

	// Best-effort program names so each link's prog can be labelled in a tooltip.
	if progs, perr := client.ListPrograms(ctx, &pb.ListProgramsRequest{}); perr == nil {
		data.Programs = progs.GetPrograms()
	}
	h.render(w, "links", data)
}

// graphIndex lists the loader groups on a node, each linking to its own graph.
func (h *Handlers) graphIndex(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "graph"}
	data.Nodes, _ = h.nodes()

	progs, maps, links, err := h.fetchGraph(r, node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "graph", data)
		return
	}
	groups, _ := groupByLoader(progs, maps, links, h.hiddenLoaders)
	for _, g := range groups {
		data.GraphGroups = append(data.GraphGroups, groupSummary{
			ID: g.ID, Label: g.Label,
			Progs: len(g.Progs), Maps: len(g.Maps), Links: len(g.Links),
		})
	}
	h.render(w, "graph", data)
}

// graphGroup renders the dependency diagram for a single loader group.
func (h *Handlers) graphGroup(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "graph"}
	data.Nodes, _ = h.nodes()

	progs, maps, links, err := h.fetchGraph(r, node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "graphgroup", data)
		return
	}
	groups, mapByID := groupByLoader(progs, maps, links, h.hiddenLoaders)
	want := r.PathValue("group")
	for _, g := range groups {
		if g.ID == want {
			data.GroupLabel = g.Label
			data.Mermaid = buildGroupMermaid(g, mapByID, node)
			h.render(w, "graphgroup", data)
			return
		}
	}
	data.Err = "unknown loader group: " + want
	h.render(w, "graphgroup", data)
}

// graphProgram renders a graph focused on a single program: its attaching links
// and the maps it references.
func (h *Handlers) graphProgram(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "graph"}
	data.Nodes, _ = h.nodes()

	id, cerr := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if cerr != nil {
		http.Error(w, "bad program id", http.StatusBadRequest)
		return
	}

	progs, maps, links, err := h.fetchGraph(r, node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "graphgroup", data)
		return
	}
	prog := findProg(progs, uint32(id))
	if prog == nil {
		data.Err = fmt.Sprintf("program %d not found", id)
		h.render(w, "graphgroup", data)
		return
	}

	mapByID := map[uint32]*pb.MapInfo{}
	for _, m := range maps {
		mapByID[m.GetId()] = m
	}
	data.GroupLabel = fmt.Sprintf("prog %d: %s", prog.GetId(), prog.GetName())
	data.Mermaid = buildGroupMermaid(programGroupData(prog, links), mapByID, node)
	h.render(w, "graphgroup", data)
}

// fetchGraph dials the node's agent and returns its programs/maps/links.
// Programs are required; maps and links are best-effort.
func (h *Handlers) fetchGraph(r *http.Request, node string) ([]*pb.ProgramInfo, []*pb.MapInfo, []*pb.LinkInfo, error) {
	conn, err := h.dial(node)
	if err != nil {
		return nil, nil, nil, err
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	progs, err := client.ListPrograms(ctx, &pb.ListProgramsRequest{})
	if err != nil {
		return nil, nil, nil, err
	}
	var maps []*pb.MapInfo
	if ml, merr := client.ListMaps(ctx, &pb.ListMapsRequest{}); merr == nil {
		maps = ml.GetMaps()
	}
	var links []*pb.LinkInfo
	if ll, lerr := client.ListLinks(ctx, &pb.ListLinksRequest{}); lerr == nil {
		links = ll.GetLinks()
	}
	return progs.GetPrograms(), maps, links, nil
}

func findProg(progs []*pb.ProgramInfo, id uint32) *pb.ProgramInfo {
	for _, p := range progs {
		if p.GetId() == id {
			return p
		}
	}
	return nil
}

// nodes returns the sorted node names of discovered agents.
func (h *Handlers) nodes() ([]string, error) {
	eps, err := h.disc.Endpoints()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(eps))
	for _, e := range eps {
		names = append(names, e.Node)
	}
	return names, nil
}

// dial opens a gRPC connection to the agent on the named node. Transport is
// plaintext within the cluster (see the mTLS follow-up in README.md).
func (h *Handlers) dial(node string) (*grpc.ClientConn, error) {
	eps, err := h.disc.Endpoints()
	if err != nil {
		return nil, err
	}
	for _, e := range eps {
		if e.Node == node {
			return grpc.NewClient(e.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
	}
	return nil, &nodeNotFoundError{node}
}

func (h *Handlers) render(w http.ResponseWriter, page string, data pageData) {
	t, ok := h.pages[page]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

func mapName(maps []*pb.MapInfo, id uint32) string {
	for _, m := range maps {
		if m.GetId() == id {
			return m.GetName()
		}
	}
	return ""
}

func progName(progs []*pb.ProgramInfo, id uint32) string {
	for _, p := range progs {
		if p.GetId() == id {
			return p.GetName()
		}
	}
	return ""
}

// progLoader returns "comm (pid)" for the loader of program id — its smallest
// holder PID, matching how the dependency graph picks a program's loader group.
// Returns "" when the program is unknown or has no holder (pinned/link-held).
func progLoader(progs []*pb.ProgramInfo, id uint32) string {
	for _, p := range progs {
		if p.GetId() != id {
			continue
		}
		best := loaderRef(p)
		if best == nil {
			return ""
		}
		return fmt.Sprintf("%s (%d)", best.GetComm(), best.GetPid())
	}
	return ""
}

// loaderRef picks the process treated as a program's loader: its smallest holder
// PID, the same choice the dependency graph makes. Returns nil when nothing
// holds an fd to the program.
func loaderRef(p *pb.ProgramInfo) *pb.ProcessRef {
	var best *pb.ProcessRef
	for _, r := range p.GetPids() {
		if best == nil || r.GetPid() < best.GetPid() {
			best = r
		}
	}
	return best
}

// mapLoaders infers the loaders of a map that nothing holds an fd to, from the
// programs referencing it: a loader closes a map's fd once the program is
// loaded (always so for .rodata/.bss, which loaders never keep), leaving the map
// alive on the program's kernel reference alone. Each entry reads
// "comm(pid) via prog <ids>", one per distinct loader, in program-id order.
func mapLoaders(progs []*pb.ProgramInfo, id uint32) []string {
	type loader struct {
		ref   *pb.ProcessRef
		progs []string
	}
	byPID := map[uint32]*loader{}
	var order []uint32

	for _, p := range progs {
		if !refsMap(p, id) {
			continue
		}
		ref := loaderRef(p)
		if ref == nil {
			continue // the referencing program has no holder either
		}
		l, ok := byPID[ref.GetPid()]
		if !ok {
			l = &loader{ref: ref}
			byPID[ref.GetPid()] = l
			order = append(order, ref.GetPid())
		}
		l.progs = append(l.progs, strconv.FormatUint(uint64(p.GetId()), 10))
	}

	out := make([]string, 0, len(order))
	for _, pid := range order {
		l := byPID[pid]
		out = append(out, fmt.Sprintf("%s(%d) via prog %s",
			l.ref.GetComm(), l.ref.GetPid(), strings.Join(l.progs, ", ")))
	}
	return out
}

func refsMap(p *pb.ProgramInfo, id uint32) bool {
	for _, mid := range p.GetMapIds() {
		if mid == id {
			return true
		}
	}
	return false
}

type nodeNotFoundError struct{ node string }

func (e *nodeNotFoundError) Error() string { return "no agent for node " + e.node }
