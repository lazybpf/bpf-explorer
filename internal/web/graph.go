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
	Label string // e.g. "systemd(1)", or the no-loader group's own words
	Progs []*pb.ProgramInfo
	Maps  []uint32 // referenced map ids (deduped, ordered); labels via mapByID
	Links []*pb.LinkInfo
}

// groupByLoader partitions objects into per-loader groups. A program's loader is
// its smallest holder PID that is not in hidden, or - for a program nothing
// holds an fd to - the loader of a program array holding it in a tail-call slot
// (see progGroups); only a program neither route reaches falls into the "no
// loader" group. Each group includes every map its programs
// reference, so a map shared across loaders appears on each of their pages, plus
// the maps it holds an fd to that no program uses, plus the inner maps of any
// map-of-maps it is credited with. Only a map nothing points at - no holder, no
// referencing program that has one, and no outer map holding it in a slot - is
// a no-loader map.
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

	// groupLabel: group id -> its label, to credit a map to.
	progGroup, groupLabel := progGroups(sortedProgs, sortedMaps, hidden)
	for _, p := range sortedProgs {
		id := progGroup[p.GetId()]
		g := getGroup(id, groupLabel[id])
		g.Progs = append(g.Progs, p)
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
	refGroup := map[uint32]string{} // map id -> group of a program referencing it
	for _, p := range sortedProgs {
		for _, mid := range p.GetMapIds() {
			referenced[mid] = true
			if g := progGroup[p.GetId()]; g != unattachedGroupID {
				known[mid] = true
				if _, ok := refGroup[mid]; !ok {
					refGroup[mid] = g // lowest prog id wins; sortedProgs is in that order
				}
			}
		}
	}
	for _, m := range sortedMaps {
		if id, _ := holderGroup(m.GetPids(), hidden); id != unattachedGroupID {
			known[m.GetId()] = true
		}
	}

	// A third route, and the only one that reaches an inner map of an
	// ArrayOfMaps/HashOfMaps: the outer map's slot. Nothing holds such a map's
	// fd, nothing pins it and no program names it in map_ids - the loader
	// inserts it and closes the fd - so both routes above miss it and it would
	// land under "no loader" while the maps page credits it to the outer map's
	// loader as "comm(pid) via map <id>". Inherit the outer map's group, which
	// is what innerMapLoaders shows, so the two stay one partition.
	innerGroup := map[uint32]string{}
	innerLabel := map[uint32]string{}
	for _, m := range sortedMaps {
		id, label := holderGroup(m.GetPids(), hidden)
		if id == unattachedGroupID {
			// The outer map may be held only by a program referencing it, in
			// which case that program's group named itself in groupLabel.
			id = refGroup[m.GetId()]
			label = groupLabel[id]
		}
		if id == "" || id == unattachedGroupID {
			continue // the outer map has no loader to pass on
		}
		for _, mid := range m.GetInnerMapIds() {
			if _, ok := innerGroup[mid]; ok {
				continue // already inherited from a lower-numbered outer map
			}
			innerGroup[mid], innerLabel[mid] = id, label
			known[mid] = true
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
		if id == unattachedGroupID {
			if inherited, ok := innerGroup[m.GetId()]; ok {
				id, label = inherited, innerLabel[m.GetId()]
			}
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

// progGroups assigns every program to a loader group, and returns each group's
// label alongside. Two routes, in order:
//
//   - the program's own lowest visible holder, and
//   - for a program nothing holds an fd to, the loader of a program array
//     holding it in a tail-call slot - itself either that array's own holder or
//     the loader of a program referencing it, the two routes the maps page
//     already credits a map by.
//
// The second is the only one that reaches a tail-call target: the loader
// inserts the program into the table and closes its fd, and only the entry
// program of the chain keeps a link. It is what progArrayLoaders shows in the
// programs page's Holders column, so the column and every count built from this
// partition stay one answer. Inheritance is one level deep - an array is
// credited from programs grouped by their own holders alone - so a chain of
// tail calls cannot loop back into it.
//
// Every caller that groups programs goes through here: the loaders index, the
// ?loader= filter and the picker on the programs page.
func progGroups(progs []*pb.ProgramInfo, maps []*pb.MapInfo, hidden map[uint32]bool) (progGroup map[uint32]string, groupLabel map[string]string) {
	sorted := append([]*pb.ProgramInfo(nil), progs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].GetId() < sorted[j].GetId() })

	progGroup = make(map[uint32]string, len(sorted))
	groupLabel = map[string]string{}
	for _, p := range sorted {
		id, label := loaderGroup(p, hidden)
		progGroup[p.GetId()] = id
		groupLabel[id] = label
	}

	// Which group each map can pass on: the group of the lowest-numbered
	// program referencing it, for an array whose own fd nobody holds.
	refGroup := map[uint32]string{}
	for _, p := range sorted {
		g := progGroup[p.GetId()]
		if g == unattachedGroupID {
			continue
		}
		for _, mid := range p.GetMapIds() {
			if _, ok := refGroup[mid]; !ok {
				refGroup[mid] = g
			}
		}
	}

	sortedMaps := append([]*pb.MapInfo(nil), maps...)
	sort.Slice(sortedMaps, func(i, j int) bool { return sortedMaps[i].GetId() < sortedMaps[j].GetId() })
	for _, m := range sortedMaps {
		id, label := holderGroup(m.GetPids(), hidden)
		if id == unattachedGroupID {
			id = refGroup[m.GetId()]
			label = groupLabel[id]
		}
		if id == "" || id == unattachedGroupID {
			continue // the array has no loader to pass on
		}
		for _, pid := range m.GetProgIds() {
			if g, ok := progGroup[pid]; !ok || g != unattachedGroupID {
				// Gone from the listing, or holding its own fd: a program is
				// credited to a tail-call slot only as a last resort, and only
				// the lowest-numbered array gets to do it.
				continue
			}
			progGroup[pid], groupLabel[id] = id, label
		}
	}
	return progGroup, groupLabel
}

// loaderGroup returns the group id and label for a program: its smallest holder
// PID not in hidden (with comm), or the no-loader group when none is visible.
// The rule for a program nothing holds is in progGroups, which is what every
// caller grouping programs should use.
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
		fmt.Sprintf("%s(%d)", sanitizeLabel(best.GetComm()), best.GetPid())
}

// loaderGroupID names a loader by its PID. Several places have to agree on this
// spelling - the loaders index, the {group} segment of a diagram URL, and the
// ?loader= filter on the programs, maps and links pages - so it is written once
// here.
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

// filterProgramsByLoader keeps the programs belonging to one loader group. It
// needs no trip through groupByLoader the way the maps filter does: progGroups
// is the partition itself - the whole rule for a program, and what the other two
// filters are derived from - so there is nothing here that could drift from it.
// The maps are part of that rule, for a program held only by a tail-call slot.
// Rows come back in the order they were listed in.
//
// Also returns the group's label, or "" when nothing on the node is in the
// group.
func filterProgramsByLoader(progs []*pb.ProgramInfo, maps []*pb.MapInfo, hidden map[uint32]bool, group string) ([]*pb.ProgramInfo, string) {
	progGroup, groupLabel := progGroups(progs, maps, hidden)
	var out []*pb.ProgramInfo
	var label string
	for _, p := range progs {
		if progGroup[p.GetId()] != group {
			continue
		}
		label = groupLabel[group]
		out = append(out, p)
	}
	return out, label
}

// filterLinksByLoader keeps the links belonging to one loader group, partitioned
// exactly as groupByLoader does it, so the count on the loaders index and the
// rows here can never disagree. Also returns the group's label when a program
// in it supplies one - "" when nothing on the node is in the group.
func filterLinksByLoader(progs []*pb.ProgramInfo, links []*pb.LinkInfo, maps []*pb.MapInfo, hidden map[uint32]bool, group string) ([]*pb.LinkInfo, string) {
	// Through progGroups, not loaderGroup: a link follows its program's group,
	// and that group can come from a program array's tail-call slot.
	progGroup, groupLabel := progGroups(progs, maps, hidden)
	var label string
	for _, p := range progs {
		if progGroup[p.GetId()] == group {
			label = groupLabel[group]
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
// the group's label, or "" when nothing on the node is in the group.
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
	return out, g.Label
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
// that has something to narrow to, counted by count. Every picker goes through
// groupByLoader, so the groups they offer, the loaders index's counts and the
// filtered rows are all one partition.
func loaderChoicesFor(groups []*loaderGroupData, count func(*loaderGroupData) int) []loaderChoice {
	var out []loaderChoice
	for _, g := range groups {
		n := count(g)
		if n == 0 {
			continue // nothing to narrow to
		}
		out = append(out, loaderChoice{Group: g.ID, Label: g.Label, Count: n})
	}
	return out
}

// linkLoaderChoices lists the loader groups that have links, for the links
// page's picker - so the filter can be reached on the page itself, not only by
// arriving from the loaders index. The maps come along because a link follows
// its program's group, and a program can be grouped by a tail-call slot.
func linkLoaderChoices(progs []*pb.ProgramInfo, links []*pb.LinkInfo, maps []*pb.MapInfo, hidden map[uint32]bool) []loaderChoice {
	groups, _ := groupByLoader(progs, maps, links, hidden)
	return loaderChoicesFor(groups, func(g *loaderGroupData) int { return len(g.Links) })
}

// mapLoaderChoices is the same for the maps page. Links play no part in grouping
// maps and are not fetched for it.
func mapLoaderChoices(progs []*pb.ProgramInfo, maps []*pb.MapInfo, hidden map[uint32]bool) []loaderChoice {
	groups, _ := groupByLoader(progs, maps, nil, hidden)
	return loaderChoicesFor(groups, func(g *loaderGroupData) int { return len(g.Maps) })
}

// programLoaderChoices is the same for the programs page. Links play no part in
// grouping programs and are not fetched for it; the maps carry the tail-call
// slots a program with no holder of its own is grouped by.
func programLoaderChoices(progs []*pb.ProgramInfo, maps []*pb.MapInfo, hidden map[uint32]bool) []loaderChoice {
	groups, _ := groupByLoader(progs, maps, nil, hidden)
	return loaderChoicesFor(groups, func(g *loaderGroupData) int { return len(g.Progs) })
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
	// An ArrayOfMaps/HashOfMaps holds its inner maps in slots, and that slot is
	// the only reference to an inner map anywhere - nothing holds its fd and no
	// program names it in map_ids - so without this edge an inner map sits on
	// the diagram unconnected to what keeps it alive. Same declared-only rule as
	// above, and a per-outer-map seen set because the same inner map can sit in
	// several slots of one outer map.
	for _, mid := range g.Maps {
		seen := map[uint32]bool{}
		for _, inner := range mapByID[mid].GetInnerMapIds() {
			if !declared[inner] || seen[inner] {
				continue
			}
			seen[inner] = true
			fmt.Fprintf(&b, "  map_%d -->|holds| map_%d\n", mid, inner)
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
// the maps a map-of-maps slot joins it to - the inner maps it holds, and the
// outer maps holding it - the programs referencing any of those, and the links
// attaching those programs. The neighbours are here because that slot is the
// only reference an inner map has anywhere: without them an inner map's page is
// one lone node with nothing to say who made it, and an outer map's page hides
// everything it holds. Pulling in the programs referencing a neighbour is what
// draws the chain an inner map is actually reached by - prog -> outer -> inner -
// since no program names the inner map itself.
//
// Programs and links are ordered by id so the diagram is stable across
// requests; maps keep the focused map first, then the outer maps and the inner
// ones in the outer map's slot order.
func mapGroupData(id uint32, progs []*pb.ProgramInfo, maps []*pb.MapInfo, links []*pb.LinkInfo) *loaderGroupData {
	g := &loaderGroupData{Maps: []uint32{id}}
	seen := map[uint32]bool{id: true}
	addMap := func(mid uint32) {
		if seen[mid] {
			return // the same inner map in two slots, or already the focus
		}
		seen[mid] = true
		g.Maps = append(g.Maps, mid)
	}
	for _, m := range maps {
		if holdsInner(m, id) {
			addMap(m.GetId())
		}
		if m.GetId() == id {
			for _, inner := range m.GetInnerMapIds() {
				addMap(inner)
			}
		}
	}

	for _, p := range progs {
		if refsAnyMap(p, g.Maps) {
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

// graphHeading is a diagram page's heading with the name kept apart from the
// words around it. The h2 is uppercase chrome, and a name the node handed us -
// a loader's comm, a program's or a map's name - has to survive that as it was
// written, since it is what the reader matches against the list they came from.
// Prefix is what this page is called, Suffix the kernel's word for the kind.
type graphHeading struct {
	Prefix string // "loader:", "prog 5:", "map 12:"
	Name   string // "agent(1000)", "trace_conn", "m_a"
	Suffix string // "(kprobe)", "(Hash)"
}

// Text puts the parts back into one string, for somewhere that takes no markup:
// the <title>, where the case distinction cannot be drawn anyway.
func (g graphHeading) Text() string {
	parts := make([]string, 0, 3)
	for _, p := range []string{g.Prefix, g.Name, g.Suffix} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, " ")
}

// loaderGroupHeading names a diagram page after its group. A label is bare -
// the loaders index has a column header to say what these are, this page does
// not - so the word is put back here, in front of the comm the node reported.
// The residual group's label is not a name at all - nothing in it came from the
// node - so it stays whole and reads as the chrome it is.
func loaderGroupHeading(label string) graphHeading {
	if label == unattachedLabel {
		return graphHeading{Prefix: label}
	}
	return graphHeading{Prefix: "loader:", Name: label}
}

func progHeading(p *pb.ProgramInfo) graphHeading {
	return graphHeading{
		Prefix: fmt.Sprintf("prog %d:", p.GetId()),
		Name:   sanitizeLabel(p.GetName()),
		Suffix: fmt.Sprintf("(%s)", sanitizeLabel(p.GetType())),
	}
}

// mapHeading is the same split for a map. A map with no name is all prefix:
// there is nothing to keep the case of.
func mapHeading(id uint32, m *pb.MapInfo) graphHeading {
	if m == nil || m.GetName() == "" {
		return graphHeading{Prefix: fmt.Sprintf("map %d", id)}
	}
	return graphHeading{
		Prefix: fmt.Sprintf("map %d:", id),
		Name:   sanitizeLabel(m.GetName()),
		Suffix: fmt.Sprintf("(%s)", sanitizeLabel(m.GetType())),
	}
}

// mapLabel is that heading as one string, for a mermaid node label - the
// diagram draws its own text and has no chrome to keep a name out of.
func mapLabel(id uint32, m *pb.MapInfo) string {
	return mapHeading(id, m).Text()
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
