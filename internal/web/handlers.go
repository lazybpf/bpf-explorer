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
		"mapLoaders": mapLoaders, "hexASCII": hexASCII, "tabClass": tabClass,
		"holders": holders, "comma": comma,
		// Exposed as a func so every page gets it without threading it through
		// each handler's pageData.
		"version": version.String,
	}
	pages := map[string]*template.Template{}
	for _, name := range []string{"index", "maps", "mapdump", "programs", "progdump",
		"links", "loaders", "loader", "tracelog", "utils"} {
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
	mux.HandleFunc("GET /nodes/{node}/loaders", h.loadersIndex)
	// The per-program and per-map diagrams are not loaders, but they share the
	// loader tab and its template; they keep this prefix until the URLs get a
	// proper pass. Neither collides with {group} below, which is one segment.
	mux.HandleFunc("GET /nodes/{node}/loaders/prog/{id}", h.programGraph)
	mux.HandleFunc("GET /nodes/{node}/loaders/map/{id}", h.mapGraph)
	mux.HandleFunc("GET /nodes/{node}/loaders/{group}", h.loaderGraph)
	mux.HandleFunc("GET /nodes/{node}/tracelog", h.tracelog)
	mux.HandleFunc("GET /nodes/{node}/tracelog/stream", h.tracelogStream)
	mux.HandleFunc("GET /nodes/{node}/utils", h.utils)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return mux
}

// pageData is the template model shared by all pages.
type pageData struct {
	// Title is the browser tab title and Sub says whether this page sits under
	// its tab rather than being it. Both are filled in by render from the page
	// name and the data below - handlers do not set them.
	Title      string
	Sub        bool
	Nodes      []string
	Node       string
	Tab        string
	Err        string
	Maps       []*pb.MapInfo
	Programs   []*pb.ProgramInfo
	Links      []*pb.LinkInfo
	MapsByID   map[uint32]*pb.MapInfo // id -> map, for program map-ref tooltips
	Dump       *dumpView
	ProgDump   *progDumpView
	Mermaid    template.HTML   // dependency diagram definition
	GraphLabel string          // heading for a diagram page: a loader, a program or a map
	Loaders    []loaderSummary // loader roster for the loaders index page
	Lookup     *lookupView     // the utils page: what was asked, and the answer
}

// lookupView is the utils page model. The typed-in values come back so the form
// keeps them, and each lookup carries its own error: a bad inode must not
// swallow a good pid.
type lookupView struct {
	Inode    string
	Device   string
	PID      string
	InodeErr string
	PIDErr   string

	// Walk records that the filesystem search was asked for, and under which
	// root, so the form and the "search the filesystem" offer stay in step.
	Walk     bool
	WalkRoot string
	Stats    *pb.WalkStats

	// Searched records that an inode lookup actually ran, which is what makes an
	// empty Matches meaningful. Scanned is how many processes it looked through:
	// zero means /proc was not visible to the agent, and then no answer at all
	// can be read into the emptiness.
	Searched bool
	Scanned  uint32
	Matches  []*pb.InodeMatch

	Process *pb.DescribeProcessResponse

	// Parent is what /proc says about Process's parent, fetched alongside it:
	// a pid on its own rarely settles anything, and what launched it is the
	// next question. Nil when there is no parent to ask about, or when asking
	// failed - it is an extra, and must not cost the answer that was asked for.
	Parent *pb.DescribeProcessResponse
}

// ParentComm names Parent for the ppid link. "?" when there is no name to give,
// the same shorthand the inode holders use for a process that has none.
func (l *lookupView) ParentComm() string {
	if !l.Parent.GetFound() || l.Parent.GetComm() == "" {
		return "?"
	}
	return l.Parent.GetComm()
}

// loaderSummary is one row of the loaders index: a loader and how many objects
// it owns, linking to its dependency diagram.
type loaderSummary struct {
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
	Lines     []xlatedLine
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

	// A map id asks for one map's contents, which get their own page: the list it
	// was opened from is still in the tab behind it, so repeating it is noise.
	idStr := r.PathValue("id")
	page := "maps"
	if idStr != "" {
		page = "mapdump"
	}

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, page, data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// The list page needs every map; the dump page needs this one's name.
	list, err := client.ListMaps(ctx, &pb.ListMapsRequest{})
	if err != nil {
		data.Err = err.Error()
		h.render(w, page, data)
		return
	}
	data.Maps = list.GetMaps()

	if idStr == "" {
		// Best-effort programs so a map nothing holds an fd to can still name the
		// loader of a program referencing it - a Holders column only the list has.
		// A failure here must not break the page.
		if progs, perr := client.ListPrograms(ctx, &pb.ListProgramsRequest{}); perr == nil {
			data.Programs = progs.GetPrograms()
		}
		h.render(w, page, data)
		return
	}

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
	h.render(w, page, data)
}

func (h *Handlers) programs(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "programs"}
	data.Nodes, _ = h.nodes()

	// As in maps: one program's xlated listing gets its own page rather than
	// repeating the list it was opened from.
	idStr := r.PathValue("id")
	page := "programs"
	if idStr != "" {
		page = "progdump"
	}

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, page, data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	list, err := client.ListPrograms(ctx, &pb.ListProgramsRequest{})
	if err != nil {
		data.Err = err.Error()
		h.render(w, page, data)
		return
	}
	data.Programs = list.GetPrograms()

	// Best-effort map metadata, so a map reference can say which map it is: a
	// tooltip on the list's map-ref column, and on the map a dump's listing
	// loads. A failure here must not break the page.
	if maps, merr := client.ListMaps(ctx, &pb.ListMapsRequest{}); merr == nil {
		data.MapsByID = mapsByID(maps.GetMaps())
	}

	if idStr == "" {
		h.render(w, page, data)
		return
	}

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
			Lines:     xlatedLines(dump.GetLines(), node, data.MapsByID),
			Available: dump.GetAvailable(),
			Note:      dump.GetNote(),
		}
	}
	h.render(w, page, data)
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

// utils answers the two questions a map full of raw numbers raises: which file
// is this inode, and which process is this pid. Both are query parameters rather
// than form posts, so an answer can be linked to or reloaded.
func (h *Handlers) utils(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "utils"}
	data.Nodes, _ = h.nodes()

	q := r.URL.Query()
	look := &lookupView{
		Inode:    strings.TrimSpace(q.Get("inode")),
		Device:   strings.TrimSpace(q.Get("dev")),
		PID:      strings.TrimSpace(q.Get("pid")),
		Walk:     q.Get("walk") != "",
		WalkRoot: strings.TrimSpace(q.Get("root")),
	}
	data.Lookup = look

	var inode uint64
	if look.Inode != "" {
		n, err := parseInode(look.Inode)
		switch {
		case err != nil:
			look.InodeErr = err.Error()
		case look.Device != "" && !validDevice(look.Device):
			look.InodeErr = `device must be "major:minor" in decimal, as the mount table prints it - e.g. 253:1`
		default:
			inode = n
		}
	}
	var pid uint64
	if look.PID != "" {
		n, err := strconv.ParseUint(look.PID, 10, 32)
		if err != nil {
			look.PIDErr = "pid must be a positive number"
		} else {
			pid = n
		}
	}
	if inode == 0 && pid == 0 {
		h.render(w, "utils", data)
		return
	}

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "utils", data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	// Longer than a list call: an inode lookup reads every process's fds and
	// mappings, which on a busy node is tens of thousands of small reads. A walk
	// gets its own budget on the agent and a client timeout above it, so partial
	// results come back with an honest "gave up" rather than a dead request.
	timeout := 30 * time.Second
	if look.Walk {
		timeout = walkSeconds*time.Second + 30*time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	if inode != 0 {
		resp, err := client.ResolveInode(ctx, &pb.ResolveInodeRequest{
			Inode:       inode,
			Device:      look.Device,
			Walk:        look.Walk,
			WalkRoot:    look.WalkRoot,
			WalkSeconds: walkSeconds,
		})
		if err != nil {
			data.Err = err.Error()
		} else {
			look.Searched = true
			look.Scanned = resp.GetProcessesScanned()
			look.Matches = resp.GetMatches()
			look.Stats = resp.GetWalk()
		}
	}
	if pid != 0 {
		resp, err := client.DescribeProcess(ctx, &pb.DescribeProcessRequest{Pid: uint32(pid)})
		if err != nil {
			// An inode error already shown stays: both lookups failing has one
			// cause, and the first message names it.
			if data.Err == "" {
				data.Err = err.Error()
			}
		} else {
			look.Process = resp
			// Pid 0 is the kernel's own ancestor, so only a real parent is
			// worth a second call. A failure here is dropped: the parent is a
			// convenience, and the process that was asked about has answered.
			if resp.GetFound() && resp.GetPpid() != 0 {
				parent, perr := client.DescribeProcess(ctx, &pb.DescribeProcessRequest{Pid: resp.GetPpid()})
				if perr == nil {
					look.Parent = parent
				}
			}
		}
	}
	h.render(w, "utils", data)
}

// comma groups a count in threes. A walk over a real filesystem reports numbers
// in the millions, and 4120013 is not a number anyone reads at a glance.
func comma(n uint64) string {
	s := strconv.FormatUint(n, 10)
	var b strings.Builder
	for i, digit := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(digit)
	}
	return b.String()
}

// walkSeconds is how long the agent may spend walking a filesystem before it
// returns what it has. Long enough for a root filesystem of a few million files
// on warm cache, short enough that a browser tab is not left hanging - and a
// walk that runs out says so, which is the cue to narrow the root and retry.
const walkSeconds = 60

// maxHolders caps how many processes one path lists. A shared library is mapped
// by every process that links it - on this machine libc has ninety-nine holders -
// and a hundred-row cell buries the path it belongs to. The first few name the
// kind of thing holding it; the count carries the rest.
const maxHolders = 8

// holderList is one path's holders, trimmed to what a table cell can carry.
type holderList struct {
	Head []*pb.InodeHolder
	More int
}

// holders trims a path's holder list for display, lowest pid first (the inspector
// sorts them), so what is shown is stable across reloads.
func holders(all []*pb.InodeHolder) holderList {
	if len(all) <= maxHolders {
		return holderList{Head: all}
	}
	return holderList{Head: all[:maxHolders], More: len(all) - maxHolders}
}

// parseInode accepts an inode the way a map dump shows one: decimal, or hex with
// an 0x prefix. The base is explicit rather than inferred, so a leading zero
// cannot quietly turn a decimal number into an octal one.
func parseInode(s string) (uint64, error) {
	base, digits := 10, s
	for _, prefix := range []string{"0x", "0X"} {
		if rest, ok := strings.CutPrefix(s, prefix); ok {
			base, digits = 16, rest
			break
		}
	}
	n, err := strconv.ParseUint(digits, base, 64)
	if err != nil {
		return 0, fmt.Errorf("inode must be a number - decimal, or hex with an 0x prefix")
	}
	if n == 0 {
		return 0, fmt.Errorf("inode 0 is what /proc prints for a mapping with no file behind it, so nothing can hold it")
	}
	return n, nil
}

// validDevice reports whether s is a "major:minor" device number in decimal, the
// form /proc/<pid>/mountinfo and the match rows both use.
func validDevice(s string) bool {
	major, minor, ok := strings.Cut(s, ":")
	if !ok {
		return false
	}
	for _, part := range []string{major, minor} {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

// loadersIndex lists the loaders on a node, each linking to its own diagram.
func (h *Handlers) loadersIndex(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "loaders"}
	data.Nodes, _ = h.nodes()

	progs, maps, links, err := h.fetchGraph(r, node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "loaders", data)
		return
	}
	groups, _ := groupByLoader(progs, maps, links, h.hiddenLoaders)
	for _, g := range groups {
		data.Loaders = append(data.Loaders, loaderSummary{
			ID: g.ID, Label: g.Label,
			Progs: len(g.Progs), Maps: len(g.Maps), Links: len(g.Links),
		})
	}
	h.render(w, "loaders", data)
}

// loaderGraph renders the dependency diagram for a single loader.
func (h *Handlers) loaderGraph(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "loaders"}
	data.Nodes, _ = h.nodes()

	progs, maps, links, err := h.fetchGraph(r, node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "loader", data)
		return
	}
	groups, mapByID := groupByLoader(progs, maps, links, h.hiddenLoaders)
	want := r.PathValue("group")
	for _, g := range groups {
		if g.ID == want {
			data.GraphLabel = g.Label
			data.Mermaid = buildGroupMermaid(g, mapByID, node)
			h.render(w, "loader", data)
			return
		}
	}
	data.Err = "unknown loader group: " + want
	h.render(w, "loader", data)
}

// programGraph renders a diagram focused on a single program: its attaching
// links and the maps it references. It reuses the loader diagram page.
func (h *Handlers) programGraph(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "loaders"}
	data.Nodes, _ = h.nodes()

	id, cerr := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if cerr != nil {
		http.Error(w, "bad program id", http.StatusBadRequest)
		return
	}

	progs, maps, links, err := h.fetchGraph(r, node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "loader", data)
		return
	}
	prog := findProg(progs, uint32(id))
	if prog == nil {
		data.Err = fmt.Sprintf("program %d not found", id)
		h.render(w, "loader", data)
		return
	}

	mapByID := map[uint32]*pb.MapInfo{}
	for _, m := range maps {
		mapByID[m.GetId()] = m
	}
	// Same shape as the diagram's own node label, and as the map page's heading.
	data.GraphLabel = fmt.Sprintf("prog %d: %s (%s)", prog.GetId(), prog.GetName(), prog.GetType())
	data.Mermaid = buildGroupMermaid(programGroupData(prog, links), mapByID, node)
	h.render(w, "loader", data)
}

// mapGraph renders a diagram focused on a single map: the programs referencing
// it and the links attaching those programs. It reuses the loader diagram page.
func (h *Handlers) mapGraph(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "loaders"}
	data.Nodes, _ = h.nodes()

	id, cerr := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if cerr != nil {
		http.Error(w, "bad map id", http.StatusBadRequest)
		return
	}

	progs, maps, links, err := h.fetchGraph(r, node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "loader", data)
		return
	}
	mapByID := map[uint32]*pb.MapInfo{}
	for _, m := range maps {
		mapByID[m.GetId()] = m
	}
	m, ok := mapByID[uint32(id)]
	if !ok {
		data.Err = fmt.Sprintf("map %d not found", id)
		h.render(w, "loader", data)
		return
	}
	data.GraphLabel = mapLabel(m.GetId(), m)
	data.Mermaid = buildGroupMermaid(mapGroupData(uint32(id), progs, links), mapByID, node)
	h.render(w, "loader", data)
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
	data.Title = pageTitle(page, data)
	data.Sub = subPages[page]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

// subPages sit under a tab rather than being it: one map's contents, one
// program's instructions, one diagram. Their tab is the way back up, so it must
// not be painted as the page you are on.
var subPages = map[string]bool{"mapdump": true, "progdump": true, "loader": true}

// tabClass marks one entry in the tab bar. The tab whose page you are on is
// "active" - inverse video, you are here. The tab a sub-page hangs under is
// "parent": marked, because that is the section you are in, but not inverse,
// because clicking it goes somewhere (up). Everything else is unmarked.
func tabClass(tab string, sub bool, name string) string {
	if tab != name {
		return ""
	}
	if sub {
		return "parent"
	}
	return "active"
}

// pageTitle builds the browser tab title, most specific part first: every action
// link opens its own tab, so a row of tabs all reading "bpf-explorer" cannot be
// navigated. Truncation eats the tail, which is why the object comes before the
// node and the node before the app name. Falls back to naming the view when the
// object is unknown - an error page - and to the bare app name on the index.
func pageTitle(page string, data pageData) string {
	// The list pages are named by their own tab: maps, programs, links, loaders,
	// tracelog.
	what := page
	switch page {
	case "index":
		what = ""
	case "mapdump":
		what = "map dump"
		if d := data.Dump; d != nil {
			what = objectTitle("map", d.ID, d.Name) + " dump"
		}
	case "progdump":
		what = "prog xlated"
		if d := data.ProgDump; d != nil {
			what = objectTitle("prog", d.ID, d.Name) + " xlated"
		}
	case "loader":
		// GraphLabel already names the subject: a loader, a program or a map.
		what = "graph"
		if data.GraphLabel != "" {
			what = data.GraphLabel + " graph"
		}
	case "utils":
		// Name the lookup, so several of these tabs can be told apart.
		if l := data.Lookup; l != nil {
			switch {
			case l.Inode != "":
				what = "inode " + l.Inode
			case l.PID != "":
				what = "pid " + l.PID
			}
		}
	}

	parts := make([]string, 0, 3)
	if what != "" {
		parts = append(parts, what)
	}
	if data.Node != "" {
		parts = append(parts, data.Node)
	}
	return strings.Join(append(parts, "bpf-explorer"), " - ")
}

// objectTitle names one object for a tab title: "map 42: counters", or just
// "map 42" when it has no name (a .rodata section the agent could not name).
func objectTitle(kind string, id uint32, name string) string {
	if name == "" {
		return fmt.Sprintf("%s %d", kind, id)
	}
	return fmt.Sprintf("%s %d: %s", kind, id, name)
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

// progLoader returns "comm(pid)" for the loader of program id — its smallest
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
		return fmt.Sprintf("%s(%d)", best.GetComm(), best.GetPid())
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
