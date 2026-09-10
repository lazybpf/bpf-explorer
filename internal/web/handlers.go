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
		"holders": holders, "comma": comma, "registers": registerSheet,
		"nsHelp": namespaceHelp, "innerPIDs": innerPIDs, "cgroupHelp": cgroupHelp,
		"nodeLinkTitle": nodeLinkTitle,
		// Exposed as a func so every page gets it without threading it through
		// each handler's pageData.
		"version": version.String,
	}
	pages := map[string]*template.Template{}
	for _, name := range []string{"index", "node", "maps", "mapdump", "programs", "progdump",
		"links", "loaders", "loader", "tracelog", "utilpid", "utilinode"} {
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
	// The node itself, before the objects on it: what the agent can see of the
	// kernel, the cgroup layout and the container runtime.
	mux.HandleFunc("GET /nodes/{node}/node", h.nodeDetails)
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
	// One route per utility, under a tab that is a section rather than a page.
	// The bare path redirects, so a link from before the split still lands on
	// the lookup it named.
	mux.HandleFunc("GET /nodes/{node}/utils", h.utils)
	mux.HandleFunc("GET /nodes/{node}/utils/pid", h.utilPID)
	mux.HandleFunc("GET /nodes/{node}/utils/inode", h.utilInode)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return mux
}

// pageData is the template model shared by all pages.
type pageData struct {
	// Title is the browser tab title and Sub says whether this page sits under
	// its tab rather than being it. Both are filled in by render from the page
	// name and the data below - handlers do not set them.
	Title string
	Sub   bool
	Nodes []string
	Node  string
	Tab   string
	// Util names the utility within the utils tab the way Tab names the tab:
	// "pid", "inode". Empty on every page outside that section.
	Util     string
	Err      string
	Maps     []*pb.MapInfo
	Programs []*pb.ProgramInfo
	Links    []*pb.LinkInfo
	// ProgFilter, MapFilter and LinkFilter narrow Programs, Maps and Links to
	// one loader group. Nil when the page is showing everything on the node;
	// the matching *Loaders slice is what it can be narrowed to, and is filled
	// in either way - the picker is how the filter is reached without coming
	// from the loaders page.
	ProgFilter  *loaderFilter
	ProgLoaders []loaderChoice
	LinkFilter  *loaderFilter
	LinkLoaders []loaderChoice
	MapFilter   *loaderFilter
	MapLoaders  []loaderChoice
	MapsByID    map[uint32]*pb.MapInfo // id -> map, for program map-ref tooltips
	Dump        *dumpView
	ProgDump    *progDumpView
	Mermaid     template.HTML   // dependency diagram definition
	GraphLabel  string          // heading for a diagram page: a loader, a program or a map
	Loaders     []loaderSummary // loader roster for the loaders index page
	// NoLoader is that page's residual group - everything no live process
	// holds an fd to - kept out of Loaders so the roster, and the count in the
	// heading over it, are processes only.
	NoLoader *loaderSummary
	// NodeInfo is the node's own configuration - kernel, cgroups, container
	// runtime - for the node tab. Node above is the name; this is the machine.
	NodeInfo *pb.DescribeNodeResponse
	// One field per utility under the utils tab, each set only by its own
	// handler: the utilities share the tab, not a model.
	PIDLookup   *pidLookup
	InodeLookup *inodeLookup
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

// loaderRoster turns a partition into the loaders index's two parts: a row per
// loader, and the no-loader group on its own. They are kept apart because the
// page presents them apart - the residual group is set below a rule, and the
// count in the heading is a count of loaders, which that group is not.
func loaderRoster(groups []*loaderGroupData) (loaders []loaderSummary, noLoader *loaderSummary) {
	for _, g := range groups {
		row := loaderSummary{
			ID: g.ID, Label: g.Label,
			Progs: len(g.Progs), Maps: len(g.Maps), Links: len(g.Links),
		}
		if g.ID == unattachedGroupID {
			noLoader = &row
			continue
		}
		loaders = append(loaders, row)
	}
	return loaders, noLoader
}

// loaderFilter narrows a list page to a single loader group - the partition the
// loaders index counts - so a count there can be clicked through to the rows
// behind it. The programs, maps and links pages each take one.
type loaderFilter struct {
	Group string // group id: "sg_1234" or "sg_unattached"
	Label string // how the loaders index names the group, without its "loader: " prefix
	Total int    // rows on the node before filtering, for the "all loaders" way out
}

// loaderChoice is one entry in a page's loader picker: a group that has
// something to narrow to, and how many rows that is.
type loaderChoice struct {
	Group string
	Label string
	Count int
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
	// Nothing is selected yet, so the picker lands on the node tab: the first
	// entry in the bar, and the one that says what the node is before anything
	// loaded on it is read against that.
	data := pageData{Tab: "node"}
	nodes, _ := h.nodes()
	data.Nodes = nodes
	h.render(w, "index", data)
}

func (h *Handlers) maps(w http.ResponseWriter, r *http.Request) {
	// A map id asks for one map's contents, which get their own page: the list it
	// was opened from is still in the tab behind it, so repeating it is noise.
	idStr := r.PathValue("id")
	page := "maps"
	if idStr != "" {
		page = "mapdump"
	}

	// ?loader=<group> narrows the list to one loader, which is how a maps count
	// on the loaders index gets clicked through; the value is that page's group
	// id, the same spelling its diagram URL and the links filter use. A dump is
	// one map, so the filter means nothing there and is not read. As on the
	// links page a malformed group is rejected before any work is done for the
	// page: unlike a map id, reading it needs nothing from the node.
	var group, groupLabel string
	if idStr == "" {
		group = strings.TrimSpace(r.URL.Query().Get("loader"))
	}
	if group != "" {
		var ok bool
		if groupLabel, ok = parseLoaderGroup(group); !ok {
			http.Error(w, "bad loader group", http.StatusBadRequest)
			return
		}
	}

	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "maps"}
	data.Nodes, _ = h.nodes()
	if group != "" {
		// Set before anything is fetched, so that a page that ends in an error
		// still says which loader was asked for: the heading is the only trace
		// left of the click that got here. The label and the total are filled
		// in below, once there is something to fill them in from.
		data.MapFilter = &loaderFilter{Group: group, Label: groupLabel}
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
		// Programs let a map nothing holds an fd to still name the loader of a
		// program referencing it - a Holders column only the list has - and are
		// what maps are grouped by. Best-effort for the column, but not under a
		// filter: without the programs the only honest page is the error, not
		// every map on the node listed under one loader's name.
		progs, perr := client.ListPrograms(ctx, &pb.ListProgramsRequest{})
		if perr != nil && group != "" {
			data.Err = perr.Error()
			data.Maps = nil
			h.render(w, page, data)
			return
		}
		data.Programs = progs.GetPrograms()

		// Built from the unfiltered list, so the picker offers the same groups
		// whichever one is currently selected. Only when the programs were
		// actually read: without them every map groups as having no loader, and
		// offering that as a choice states something about the node that is
		// really just the failed fetch above. (Under a filter perr has already
		// returned.)
		var choices []loaderChoice
		if perr == nil {
			choices = mapLoaderChoices(data.Programs, data.Maps, h.hiddenLoaders)
		}

		if f := data.MapFilter; f != nil {
			filtered, label := filterMapsByLoader(data.Programs, data.Maps, h.hiddenLoaders, group)
			if label != "" {
				// The group's own spelling, with the loader's comm; the fallback
				// stands when nothing on the node is in this group any more.
				f.Label = label
			}
			f.Total = len(data.Maps)
			data.Maps = filtered
			if !hasLoaderChoice(choices, group) {
				// A group with no maps is not worth offering, but the one being
				// shown has to be in the list or the picker cannot say what is
				// selected - a stale link, or a loader that has since exited.
				choices = append(choices, loaderChoice{Group: group, Label: f.Label})
			}
		}
		data.MapLoaders = choices
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
	// As in maps: one program's xlated listing gets its own page rather than
	// repeating the list it was opened from.
	idStr := r.PathValue("id")
	page := "programs"
	if idStr != "" {
		page = "progdump"
	}

	// ?loader=<group> narrows the list to one loader, which is how a programs
	// count on the loaders index gets clicked through; the value is that page's
	// group id, the same spelling its diagram URL and the other two filters
	// use. An xlated listing is one program, so the filter means nothing there
	// and is not read. As on the other list pages a malformed group is rejected
	// before any work is done for the page: unlike a program id, reading it
	// needs nothing from the node.
	var group, groupLabel string
	if idStr == "" {
		group = strings.TrimSpace(r.URL.Query().Get("loader"))
	}
	if group != "" {
		var ok bool
		if groupLabel, ok = parseLoaderGroup(group); !ok {
			http.Error(w, "bad loader group", http.StatusBadRequest)
			return
		}
	}

	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "programs"}
	data.Nodes, _ = h.nodes()
	if group != "" {
		// Set before anything is fetched, so that a page that ends in an error
		// still says which loader was asked for: the heading is the only trace
		// left of the click that got here. The label and the total are filled
		// in below, once there is something to fill them in from.
		data.ProgFilter = &loaderFilter{Group: group, Label: groupLabel}
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
	// loads. A failure here must not break the page - not even under a filter,
	// unlike the links and maps pages: a program is grouped by the processes
	// holding an fd to it, which the list above already carries, so nothing
	// about the grouping depends on this call.
	if maps, merr := client.ListMaps(ctx, &pb.ListMapsRequest{}); merr == nil {
		data.MapsByID = mapsByID(maps.GetMaps())
	}

	if idStr == "" {
		// Built from the unfiltered list, so the picker offers the same groups
		// whichever one is currently selected.
		choices := programLoaderChoices(data.Programs, h.hiddenLoaders)

		if f := data.ProgFilter; f != nil {
			filtered, label := filterProgramsByLoader(data.Programs, h.hiddenLoaders, group)
			if label != "" {
				// The group's own spelling, with the loader's comm; the fallback
				// stands when nothing on the node is in this group any more.
				f.Label = label
			}
			f.Total = len(data.Programs)
			data.Programs = filtered
			if !hasLoaderChoice(choices, group) {
				// A group with no programs is not worth offering, but the one
				// being shown has to be in the list or the picker cannot say
				// what is selected - a stale link, or a loader that has since
				// exited.
				choices = append(choices, loaderChoice{Group: group, Label: f.Label})
			}
		}
		data.ProgLoaders = choices
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

// links lists the BPF links on a node, like `bpftool link show`. ?loader=<group>
// narrows the list to one loader, which is how a links count on the loaders
// index gets clicked through; the value is that page's group id, so the group,
// its diagram URL and this filter all spell a loader the same way.
func (h *Handlers) links(w http.ResponseWriter, r *http.Request) {
	// A malformed group is rejected before any work is done for the page: unlike
	// a map or program id, reading it needs nothing from the node.
	group := strings.TrimSpace(r.URL.Query().Get("loader"))
	var groupLabel string
	if group != "" {
		var ok bool
		if groupLabel, ok = parseLoaderGroup(group); !ok {
			http.Error(w, "bad loader group", http.StatusBadRequest)
			return
		}
	}

	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "links"}
	data.Nodes, _ = h.nodes()
	if group != "" {
		// Set before anything is fetched, so that a page that ends in an error
		// still says which loader was asked for: the heading is the only trace
		// left of the click that got here. The label and the total are filled
		// in below, once there is something to fill them in from.
		data.LinkFilter = &loaderFilter{Group: group, Label: groupLabel}
	}

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

	// Program names label each link's prog in a tooltip - best-effort, except
	// under a loader filter: the programs are what the links are grouped by, so
	// without them the only honest page is the error, not every link on the node
	// listed under one loader's name.
	progs, perr := client.ListPrograms(ctx, &pb.ListProgramsRequest{})
	if perr != nil && group != "" {
		data.Err = perr.Error()
		data.Links = nil
		h.render(w, "links", data)
		return
	}
	data.Programs = progs.GetPrograms()

	// Built from the unfiltered list, so the picker offers the same groups
	// whichever one is currently selected. Only when the programs were actually
	// read: without them every link groups as having no loader, and offering
	// that as a choice states something about the node that is really just the
	// failed fetch above. (Under a filter perr has already returned.)
	var choices []loaderChoice
	if perr == nil {
		choices = linkLoaderChoices(data.Programs, data.Links, h.hiddenLoaders)
	}

	if f := data.LinkFilter; f != nil {
		filtered, label := filterLinksByLoader(data.Programs, data.Links, h.hiddenLoaders, group)
		if label != "" {
			// The group's own spelling, with the loader's comm; the fallback
			// stands when nothing on the node is in this group any more.
			f.Label = label
		}
		f.Total = len(data.Links)
		data.Links = filtered
		if !hasLoaderChoice(choices, group) {
			// A group with no links is not worth offering, but the one being
			// shown has to be in the list or the picker cannot say what is
			// selected - a stale link, or a loader that has since exited.
			choices = append(choices, loaderChoice{Group: group, Label: f.Label})
		}
	}
	data.LinkLoaders = choices
	h.render(w, "links", data)
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
	data.Loaders, data.NoLoader = loaderRoster(groups)
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

// nodeLinkTitle names where a node button in the picker goes. Every tab but one
// is a view of something on the node - "maps on node-a" - while the node tab is
// the node itself, which that wording would turn into "node on node-a".
func nodeLinkTitle(tab, node string) string {
	if tab == "node" {
		return node + " itself: kernel, cgroups, container runtime"
	}
	return tab + " on " + node
}

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
	// Narrowed to one loader, a list page is about that loader, and a bookmark
	// or a history entry has to say which.
	case "links":
		if f := data.LinkFilter; f != nil {
			what = f.Label + " links"
		}
	case "maps":
		if f := data.MapFilter; f != nil {
			what = f.Label + " maps"
		}
	case "programs":
		if f := data.ProgFilter; f != nil {
			what = f.Label + " programs"
		}
	// A utility page is named by what was asked of it, so several of these tabs
	// can be told apart; by the utility itself when nothing has been asked yet.
	case "utilpid":
		what = "pid lookup"
		if l := data.PIDLookup; l != nil && l.PID != "" {
			what = "pid " + l.PID
		}
	case "utilinode":
		what = "inode lookup"
		if l := data.InodeLookup; l != nil && l.Inode != "" {
			what = "inode " + l.Inode
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
