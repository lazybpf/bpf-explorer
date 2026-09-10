package web

import (
	"fmt"
	"html/template"
	"sort"
	"strconv"
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
	Label string // e.g. "loader: systemd(1)"
	Progs []*pb.ProgramInfo
	Maps  []uint32 // referenced map ids (deduped, ordered); labels via mapByID
	Links []*pb.LinkInfo
}

// groupByLoader partitions objects into per-loader groups. A program's loader is
// its smallest holder PID that is not in hidden; programs with no visible holder
// fall into the "no loader" group. Each group includes every map its programs
// reference, so a map shared across loaders appears on each of their pages, plus
// the maps it holds an fd to that no program uses. Only a map nothing points at
// - no holder, and no referencing program that has one - is a no-loader map.
// Returns the groups in first-seen order plus a map-id lookup for labels.
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

	mapsSeen := map[string]map[uint32]bool{}
	addMap := func(g *loaderGroupData, mid uint32) {
		seen, ok := mapsSeen[g.ID]
		if !ok {
			seen = map[uint32]bool{}
			mapsSeen[g.ID] = seen
		}
		if seen[mid] {
			return // the same program referencing it twice, or two of them
		}
		seen[mid] = true
		g.Maps = append(g.Maps, mid)
	}

	// A map's loader is known when a process holds an fd to it, or when a
	// program referencing it has one. Such a map never joins the no-loader
	// group, however it got there - a tail-call target nobody holds an fd to
	// would otherwise drag its loader's whole map set in with it. The maps page
	// names that loader in its Holders column, so a row reading "tetragon(1234)"
	// listed under "no loader" is the page contradicting itself.
	referenced := map[uint32]bool{} // referenced by any program at all
	known := map[uint32]bool{}      // ...whose loader is visible, or held by one
	for _, p := range sortedProgs {
		for _, mid := range p.GetMapIds() {
			referenced[mid] = true
			if progGroup[p.GetId()] != unattachedGroupID {
				known[mid] = true
			}
		}
	}
	for _, m := range sortedMaps {
		if id, _ := holderGroup(m.GetPids(), hidden); id != unattachedGroupID {
			known[m.GetId()] = true
		}
	}

	// Each group gets every map referenced by its own programs.
	for _, g := range groupsInOrder(groups, order) {
		for _, p := range g.Progs {
			for _, mid := range p.GetMapIds() {
				if g.ID == unattachedGroupID && known[mid] {
					continue
				}
				addMap(g, mid)
			}
		}
	}
	// And whoever holds an fd to a map gets it too: a loader keeps a map alive
	// that way with no program using it yet, and that map would otherwise be
	// filed under "no loader" while its own row names the process holding it.
	// Only a map nobody holds and nobody references is left to the no-loader
	// group.
	for _, m := range sortedMaps {
		id, label := holderGroup(m.GetPids(), hidden)
		if id == unattachedGroupID && referenced[m.GetId()] {
			continue // already under whichever groups reference it
		}
		addMap(getGroup(id, label), m.GetId())
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

// groupsInOrder returns the groups in first-seen order, except that the
// no-loader group always comes last however early it was created - a program
// with no visible holder can be the lowest-numbered one on the node. It is a
// group but not a loader, so every roster built from this - the loaders index,
// both pickers - can present it as the residual bucket it is rather than as
// another process in the list.
func groupsInOrder(groups map[string]*loaderGroupData, order []string) []*loaderGroupData {
	out := make([]*loaderGroupData, 0, len(order))
	for _, id := range order {
		if id != unattachedGroupID {
			out = append(out, groups[id])
		}
	}
	if g, ok := groups[unattachedGroupID]; ok {
		out = append(out, g)
	}
	return out
}

// loaderGroup returns the group id and label for a program: its smallest holder
// PID not in hidden (with comm), or the no-loader group when none is visible.
func loaderGroup(p *pb.ProgramInfo, hidden map[uint32]bool) (id, label string) {
	return holderGroup(p.GetPids(), hidden)
}

// holderGroup is that rule on its own, so a map can be grouped by the processes
// holding an fd to it the same way a program is - one spelling of "the loader is
// the lowest-numbered visible holder", not two that could drift apart.
func holderGroup(pids []*pb.ProcessRef, hidden map[uint32]bool) (id, label string) {
	var best *pb.ProcessRef
	for _, r := range pids {
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
	return loaderGroupID(best.GetPid()),
		fmt.Sprintf("%s%s(%d)", loaderLabelPrefix, sanitizeLabel(best.GetComm()), best.GetPid())
}

// loaderLabelPrefix is how a group label names a loader on the loaders index,
// where it tells a real loader apart from the no-loader row. Where the field is
// already called "loader" - a filtered page's picker and its heading - it is
// dropped rather than saying the word twice.
const loaderLabelPrefix = "loader: "

// shortLoaderLabel drops that prefix. The no-loader label does not carry one and
// comes back unchanged.
func shortLoaderLabel(label string) string {
	return strings.TrimPrefix(label, loaderLabelPrefix)
}

// loaderGroupID names a loader by its PID. Several places have to agree on this
// spelling - the loaders index, the {group} segment of a diagram URL, and the
// ?loader= filter on the links and maps pages - so it is written once here.
func loaderGroupID(pid uint32) string { return fmt.Sprintf("sg_%d", pid) }

// parseLoaderGroup validates a group id arriving from a URL and returns a label
// to name it by. The label is a fallback: it carries no comm, because a group
// with nothing left in it has no program to read the loader's name from - which
// is exactly the case where it gets used (the loader exited between the loaders
// page being drawn and a count on it being clicked).
func parseLoaderGroup(group string) (label string, ok bool) {
	if group == unattachedGroupID {
		return unattachedLabel, true
	}
	rest, found := strings.CutPrefix(group, "sg_")
	if !found {
		return "", false
	}
	pid, err := strconv.ParseUint(rest, 10, 32)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("pid %d", pid), true
}

// filterLinksByLoader keeps the links belonging to one loader group, partitioned
// exactly as groupByLoader does it, so the count on the loaders index and the
// rows here can never disagree. Also returns the group's full label when a
// program in it supplies one - "" when nothing on the node is in the group. The
// label is the short form: this page's heading already says "links", and its
// picker is already labelled "loader".
func filterLinksByLoader(progs []*pb.ProgramInfo, links []*pb.LinkInfo, hidden map[uint32]bool, group string) ([]*pb.LinkInfo, string) {
	progGroup := make(map[uint32]string, len(progs))
	var label string
	for _, p := range progs {
		id, l := loaderGroup(p, hidden)
		progGroup[p.GetId()] = id
		if id == group {
			label = shortLoaderLabel(l)
		}
	}

	var out []*pb.LinkInfo
	for _, l := range links {
		// A link attached to no program, or to one the agent did not list, is
		// grouped with the no-loader objects - the same fallback groupByLoader
		// makes, and the reason prog id 0 lands there rather than nowhere.
		id, ok := progGroup[l.GetProgId()]
		if !ok {
			id = unattachedGroupID
		}
		if id == group {
			out = append(out, l)
		}
	}
	return out, label
}

// filterMapsByLoader keeps the maps belonging to one loader group, partitioned
// by groupByLoader itself so the count on the loaders index and the rows here
// can never disagree - the rule has enough cases now that a second copy of it
// would be a second chance to get one wrong. Rows come back in the order they
// were listed in rather than the order the group referenced them, and a map id
// the group references that ListMaps did not return has no row: that, not the
// partition, is why the picker's count can overshoot them.
//
// Unlike a link, a map can be in more than one group - two loaders' programs
// referencing the same map put it in both - so the counts down the loaders
// index's maps column can add up to more than the node has maps. Also returns
// the group's label, in the short form and for the same reason as
// filterLinksByLoader, or "" when nothing on the node is in the group.
func filterMapsByLoader(progs []*pb.ProgramInfo, maps []*pb.MapInfo, hidden map[uint32]bool, group string) ([]*pb.MapInfo, string) {
	groups, _ := groupByLoader(progs, maps, nil, hidden)
	g := groupByID(groups, group)
	if g == nil {
		return nil, ""
	}
	in := make(map[uint32]bool, len(g.Maps))
	for _, mid := range g.Maps {
		in[mid] = true
	}

	var out []*pb.MapInfo
	for _, m := range maps {
		if in[m.GetId()] {
			out = append(out, m)
		}
	}
	return out, shortLoaderLabel(g.Label)
}

// groupByID picks one group out of a partition, or nil when the node has
// nothing in it - a stale link, or a loader that has since exited.
func groupByID(groups []*loaderGroupData, id string) *loaderGroupData {
	for _, g := range groups {
		if g.ID == id {
			return g
		}
	}
	return nil
}

// loaderChoicesFor turns a partition into a page's picker: one entry per group
// that has something to narrow to, counted by count. Both pickers go through
// groupByLoader, so the groups they offer, the loaders index's counts and the
// filtered rows are all one partition.
func loaderChoicesFor(groups []*loaderGroupData, count func(*loaderGroupData) int) []loaderChoice {
	var out []loaderChoice
	for _, g := range groups {
		n := count(g)
		if n == 0 {
			continue // nothing to narrow to
		}
		out = append(out, loaderChoice{Group: g.ID, Label: shortLoaderLabel(g.Label), Count: n})
	}
	return out
}

// linkLoaderChoices lists the loader groups that have links, for the links
// page's picker - so the filter can be reached on the page itself, not only by
// arriving from the loaders index. Maps play no part in grouping links and are
// not fetched for it.
func linkLoaderChoices(progs []*pb.ProgramInfo, links []*pb.LinkInfo, hidden map[uint32]bool) []loaderChoice {
	groups, _ := groupByLoader(progs, nil, links, hidden)
	return loaderChoicesFor(groups, func(g *loaderGroupData) int { return len(g.Links) })
}

// mapLoaderChoices is the same for the maps page. Links play no part in grouping
// maps and are not fetched for it.
func mapLoaderChoices(progs []*pb.ProgramInfo, maps []*pb.MapInfo, hidden map[uint32]bool) []loaderChoice {
	groups, _ := groupByLoader(progs, maps, nil, hidden)
	return loaderChoicesFor(groups, func(g *loaderGroupData) int { return len(g.Maps) })
}

// hasLoaderChoice reports whether the picker already offers a group.
func hasLoaderChoice(choices []loaderChoice, group string) bool {
	for _, c := range choices {
		if c.Group == group {
			return true
		}
	}
	return false
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
	// Edges only to maps this group declared above. A focused diagram - one map,
	// one program - deliberately leaves out the other maps its programs
	// reference, and mermaid would otherwise invent a bare node for each. The
	// per-program seen set collapses a map a program references more than once,
	// which would otherwise draw the same arrow twice.
	declared := map[uint32]bool{}
	for _, mid := range g.Maps {
		declared[mid] = true
	}
	for _, p := range g.Progs {
		seen := map[uint32]bool{}
		for _, mid := range p.GetMapIds() {
			if !declared[mid] || seen[mid] {
				continue
			}
			seen[mid] = true
			fmt.Fprintf(&b, "  prog_%d -->|uses| map_%d\n", p.GetId(), mid)
		}
	}

	// Click-to-navigate: program -> its focused graph, map -> its details.
	for _, p := range g.Progs {
		fmt.Fprintf(&b, "  click prog_%d \"/nodes/%s/loaders/prog/%d\" \"zoom into program\"\n",
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

// mapGroupData builds a single-map pseudo-group for the per-map graph: the map,
// the programs referencing it, and the links attaching those programs. Programs
// and links are ordered by id so the diagram is stable across requests.
func mapGroupData(id uint32, progs []*pb.ProgramInfo, links []*pb.LinkInfo) *loaderGroupData {
	g := &loaderGroupData{Maps: []uint32{id}}
	for _, p := range progs {
		if refsMap(p, id) {
			g.Progs = append(g.Progs, p)
		}
	}
	sort.Slice(g.Progs, func(i, j int) bool { return g.Progs[i].GetId() < g.Progs[j].GetId() })

	for _, l := range links {
		if findProg(g.Progs, l.GetProgId()) != nil {
			g.Links = append(g.Links, l)
		}
	}
	sort.Slice(g.Links, func(i, j int) bool { return g.Links[i].GetId() < g.Links[j].GetId() })
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
