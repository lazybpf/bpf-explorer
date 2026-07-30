// Package ui runs the web frontend: it builds a discoverer (in-cluster
// Kubernetes by default, or a static list when --agents is set), wires the HTTP
// handlers, and serves them.
package ui

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/lazybpf/bpf-explorer/internal/discovery"
	"github.com/lazybpf/bpf-explorer/internal/web"
)

// hideLoaderPIDsEnv holds a comma-separated list of loader PIDs to exclude from
// the dependency-graph grouping (e.g. "1" to hide the systemd loader).
const hideLoaderPIDsEnv = "BPF_EXPLORER_HIDE_LOADER_PIDS"

// agentPort is the gRPC port the agents listen on (matches deploy/03-daemonset.yaml).
const agentPort = 50051

// Run serves the UI on addr. If staticAgents is non-empty it uses static
// discovery; otherwise it discovers agent pods via the in-cluster K8s API in
// the given namespace.
func Run(addr, namespace, staticAgents string) error {
	var (
		disc discovery.Discoverer
		err  error
	)
	if staticAgents != "" {
		disc, err = discovery.ParseStatic(staticAgents)
		if err != nil {
			return err
		}
		log.Printf("ui: static discovery: %s", staticAgents)
	} else {
		disc, err = discovery.NewKubernetes(namespace, agentPort)
		if err != nil {
			return err
		}
		log.Printf("ui: in-cluster discovery in namespace %q", namespace)
	}

	hidden := parseHiddenLoaderPIDs(os.Getenv(hideLoaderPIDsEnv))
	if len(hidden) > 0 {
		log.Printf("ui: hiding loader PIDs from graph grouping: %v", os.Getenv(hideLoaderPIDsEnv))
	}

	handlers, err := web.New(disc, hidden)
	if err != nil {
		return err
	}

	log.Printf("ui: serving on %s", addr)
	return http.ListenAndServe(addr, handlers.Router())
}

// parseHiddenLoaderPIDs parses a comma-separated PID list; invalid entries are
// skipped. Returns nil when the input is empty.
func parseHiddenLoaderPIDs(spec string) map[uint32]bool {
	var hidden map[uint32]bool
	for part := range strings.SplitSeq(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pid, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			continue
		}
		if hidden == nil {
			hidden = map[uint32]bool{}
		}
		hidden[uint32(pid)] = true
	}
	return hidden
}
