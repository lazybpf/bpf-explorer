package web

import (
	"fmt"
	"html/template"
	"sort"
	"strings"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

const (
	unattachedGroupID = "sg_unattached"
	unattachedLabel   = "no loader (pinned/link-held)"
)

// loaderGroupData is one loader's slice of the dependency graph: the programs it
// loaded, the maps those programs reference, and the links attaching them. Each
// group is rendered on its own page/URL to keep a single diagram readable.
type loaderGroupData struct {
	ID    string // mermaid-safe id, e.g. "sg_1234" or "sg_unattached"
	Label string // e.g. "loader: systemd (1)"
	Progs []*pb.ProgramInfo
	Maps  []uint32 // referenced map ids (deduped, ordered); labels via mapByID
	Links []*pb.LinkInfo
}

// groupByLoader partitions objects into per-loader groups. A program's loader is
// its smallest holder PID that is not in hidden; programs with no visible holder
// (and maps referenced by nobody) fall into the "no loader" group. Each group
// includes every map its programs reference, so a map shared across loaders
// appears on each of their pages. Returns the groups in first-seen order plus a
// map-id lookup for labels.
func groupByLoader(progs []*pb.ProgramInfo, maps []*pb.MapInfo, links []*pb.LinkInfo, hidden map[uint32]bool) ([]*loaderGroupData, map[uint32]*pb.MapInfo) {
	mapByID := map[uint32]*pb.MapInfo{}
	for _, m := range maps {
		mapByID[m.GetId()] = m
	}

	sortedProgs := append([]*pb.ProgramInfo(nil), progs...)
	sort.Slice(sortedProgs, func(i, j int) bool { return sortedProgs[i].GetId() < sortedProgs[j].GetId() })
	sortedLinks := append([]*pb.LinkInfo(nil), links...)
	sort.Slice(sortedLinks, func(i, j int) bool { return sortedLinks[i].GetId() < sortedLinks[j].GetId() })
	sortedMaps := append([]*pb.MapInfo(nil), maps...)
	sort.Slice(sortedMaps, func(i, j int) bool { return sortedMaps[i].GetId() < sortedMaps[j].GetId() })

	groups := map[string]*loaderGroupData{}
	var order []string
	getGroup := func(id, label string) *loaderGroupData {
		g, ok := groups[id]
		if !ok {
			g = &loaderGroupData{ID: id, Label: label}
			groups[id] = g
			order = append(order, id)
		}
		return g
	}

	progGroup := map[uint32]string{}
	for _, p := range sortedProgs {
		id, label := loaderGroup(p, hidden)
		g := getGroup(id, label)
		g.Progs = append(g.Progs, p)
		progGroup[p.GetId()] = id
	}

	// Each group gets every map referenced by its own programs.
	referenced := map[uint32]bool{}
	for _, g := range groupsInOrder(groups, order) {
		seen := map[uint32]bool{}
		for _, p := range g.Progs {
			for _, mid := range p.GetMapIds() {
				referenced[mid] = true
				if !seen[mid] {
					seen[mid] = true
					g.Maps = append(g.Maps, mid)
				}
			}
		}
	}
	// Maps referenced by nobody land in the no-loader group.
	for _, m := range sortedMaps {
		if !referenced[m.GetId()] {
			getGroup(unattachedGroupID, unattachedLabel).Maps = append(
				getGroup(unattachedGroupID, unattachedLabel).Maps, m.GetId())
		}
	}

	for _, l := range sortedLinks {
		id, ok := progGroup[l.GetProgId()]
		if !ok {
			id = getGroup(unattachedGroupID, unattachedLabel).ID
		}
		groups[id].Links = append(groups[id].Links, l)
	}

	return groupsInOrder(groups, order), mapByID
}

func groupsInOrder(groups map[string]*loaderGroupData, order []string) []*loaderGroupData {
	out := make([]*loaderGroupData, 0, len(order))
	for _, id := range order {
		out = append(out, groups[id])
	}
	return out
}

// loaderGroup returns the group id and label for a program: its smallest holder
// PID not in hidden (with comm), or the no-loader group when none is visible.
func loaderGroup(p *pb.ProgramInfo, hidden map[uint32]bool) (id, label string) {
	var best *pb.ProcessRef
	for _, r := range p.GetPids() {
		if hidden[r.GetPid()] {
			continue
		}
		if best == nil || r.GetPid() < best.GetPid() {
			best = r
		}
	}
	if best == nil {
		return unattachedGroupID, unattachedLabel
	}
	return fmt.Sprintf("sg_%d", best.GetPid()),
		fmt.Sprintf("loader: %s (%d)", sanitizeLabel(best.GetComm()), best.GetPid())
}

// buildGroupMermaid renders the mermaid diagram for a group of programs:
// programs (rectangles), the maps they reference (cylinders), and the links
// attaching them (hexagons). Program nodes link to their per-program graph and
// map nodes to the map's details page, so a user can zoom in from a busy graph
// (requires securityLevel 'loose' in the page). node is used to build those URLs.
func buildGroupMermaid(g *loaderGroupData, mapByID map[uint32]*pb.MapInfo, node string) template.HTML {
	var b strings.Builder
	b.WriteString("graph LR\n")

	for _, p := range g.Progs {
		fmt.Fprintf(&b, "  prog_%d[\"prog %d: %s (%s)\"]\n",
			p.GetId(), p.GetId(), sanitizeLabel(p.GetName()), sanitizeLabel(p.GetType()))
	}
	for _, mid := range g.Maps {
		fmt.Fprintf(&b, "  map_%d[(\"%s\")]\n", mid, mapLabel(mid, mapByID[mid]))
	}
	for _, l := range g.Links {
		label := sanitizeLabel(l.GetType())
		if a := sanitizeLabel(l.GetAttach()); a != "" {
			label += " " + a
		}
		fmt.Fprintf(&b, "  link_%d{{\"link %d: %s\"}}\n", l.GetId(), l.GetId(), label)
	}

	for _, l := range g.Links {
		if l.GetProgId() != 0 {
			fmt.Fprintf(&b, "  link_%d -->|attaches| prog_%d\n", l.GetId(), l.GetProgId())
		}
	}
	for _, p := range g.Progs {
		for _, mid := range p.GetMapIds() {
			fmt.Fprintf(&b, "  prog_%d -->|uses| map_%d\n", p.GetId(), mid)
		}
	}

	// Click-to-navigate: program -> its focused graph, map -> its details.
	for _, p := range g.Progs {
		fmt.Fprintf(&b, "  click prog_%d \"/nodes/%s/graph/prog/%d\" \"zoom into program\"\n",
			p.GetId(), node, p.GetId())
	}
	for _, mid := range g.Maps {
		fmt.Fprintf(&b, "  click map_%d \"/nodes/%s/maps/%d\" \"map details\"\n", mid, node, mid)
	}

	return template.HTML(b.String())
}

// programGroupData builds a single-program pseudo-group for the per-program
// graph: the program, the maps it references, and the links attaching it.
func programGroupData(p *pb.ProgramInfo, links []*pb.LinkInfo) *loaderGroupData {
	g := &loaderGroupData{Progs: []*pb.ProgramInfo{p}}
	seen := map[uint32]bool{}
	for _, mid := range p.GetMapIds() {
		if !seen[mid] {
			seen[mid] = true
			g.Maps = append(g.Maps, mid)
		}
	}
	for _, l := range links {
		if l.GetProgId() == p.GetId() {
			g.Links = append(g.Links, l)
		}
	}
	return g
}

func mapLabel(id uint32, m *pb.MapInfo) string {
	if m == nil || m.GetName() == "" {
		return fmt.Sprintf("map %d", id)
	}
	return fmt.Sprintf("map %d: %s (%s)", id, sanitizeLabel(m.GetName()), sanitizeLabel(m.GetType()))
}

// sanitizeLabel strips characters that would break a quoted mermaid label or
// inject markup. BPF object names are already restricted to [A-Za-z0-9_], so
// this is defensive.
func sanitizeLabel(s string) string {
	return strings.NewReplacer(
		`"`, "'", "[", "(", "]", ")", "{", "(", "}", ")",
		"|", "/", "<", "", ">", "", "&", "+", "\n", " ", "\r", " ",
	).Replace(s)
}
