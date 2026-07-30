// Package discovery finds the per-node agents the UI fans out to.
//
// Two implementations:
//   - Kubernetes (kube.go): lists agent DaemonSet pods via the in-cluster API
//     and maps each Ready pod to nodeName -> podIP:port. This is the real
//     deployment path.
//   - Static: a fixed node=addr list from --agents, handy for pointing the UI
//     at a specific agent (e.g. via kubectl port-forward) without RBAC.
package discovery

import (
	"fmt"
	"sort"
	"strings"
)

// Endpoint is one agent reachable at Addr, running on Node.
type Endpoint struct {
	Node string
	Addr string // host:port of the agent's gRPC server
}

// Discoverer returns the currently-known agent endpoints.
type Discoverer interface {
	Endpoints() ([]Endpoint, error)
}

// Static is a fixed set of endpoints, e.g. from --agents.
type Static struct{ endpoints []Endpoint }

// ParseStatic builds a Static discoverer from a comma-separated spec. Each item
// is "node=host:port" or just "host:port" (the address doubles as the label).
func ParseStatic(spec string) (*Static, error) {
	var eps []Endpoint
	for _, raw := range strings.Split(spec, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		node, addr := item, item
		if name, a, ok := strings.Cut(item, "="); ok {
			node, addr = strings.TrimSpace(name), strings.TrimSpace(a)
		}
		if addr == "" {
			return nil, fmt.Errorf("empty address in %q", raw)
		}
		eps = append(eps, Endpoint{Node: node, Addr: addr})
	}
	if len(eps) == 0 {
		return nil, fmt.Errorf("no agents in %q", spec)
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].Node < eps[j].Node })
	return &Static{endpoints: eps}, nil
}

func (s *Static) Endpoints() ([]Endpoint, error) { return s.endpoints, nil }
