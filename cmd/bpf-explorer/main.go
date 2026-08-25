// Command bpf-explorer is a single binary that runs in one of three roles,
// selected with --role, so one image serves both the DaemonSet agent and the
// UI Deployment:
//
//	bpf-explorer --role=agent --listen=:50051
//	bpf-explorer --role=ui    --listen=:8080 --namespace=bpf-explorer
//	bpf-explorer --role=local --listen=:8080 --agent-listen=:50051
//
// The local role runs the other two together in one process, for development
// without a cluster. See runLocal.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/lazybpf/bpf-explorer/internal/agent"
	"github.com/lazybpf/bpf-explorer/internal/ui"
	"github.com/lazybpf/bpf-explorer/internal/version"
)

func main() {
	role := flag.String("role", "", "which component to run: agent | ui | local")
	listen := flag.String("listen", "", "listen address (agent default :50051, ui and local default :8080)")
	agentListen := flag.String("agent-listen", ":50051", "local: listen address for the bundled agent")
	namespace := flag.String("namespace", "bpf-explorer", "ui: namespace to discover agent pods in")
	agents := flag.String("agents", "", "ui: static agent list (node=host:port,...); overrides in-cluster discovery")
	showVersion := flag.Bool("version", false, "print the build version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("bpf-explorer", version.String())
		return
	}
	log.Printf("bpf-explorer %s", version.String())

	switch *role {
	case "agent":
		addr := *listen
		if addr == "" {
			addr = ":50051"
		}
		if err := agent.Run(addr); err != nil {
			log.Fatalf("agent: %v", err)
		}
	case "ui":
		addr := *listen
		if addr == "" {
			addr = ":8080"
		}
		if err := ui.Run(addr, *namespace, *agents); err != nil {
			log.Fatalf("ui: %v", err)
		}
	case "local":
		addr := *listen
		if addr == "" {
			addr = ":8080"
		}
		// --agents would point the UI at some other agent while this process
		// is also running its own; that is contradictory rather than useful.
		if *agents != "" {
			log.Fatalf("--agents cannot be combined with --role=local (local runs its own agent on %s)", *agentListen)
		}
		if err := runLocal(addr, *agentListen); err != nil {
			log.Fatalf("local: %v", err)
		}
	default:
		log.Fatalf("--role must be 'agent', 'ui' or 'local' (got %q)", *role)
	}
}

// runLocal runs the agent and the UI in one process, with the UI's static
// discovery pointed at the bundled agent, so local development takes one
// command instead of two terminals.
//
// Both halves share the process, which means it must be started with BPF
// privileges (sudo) because the agent half needs them - the UI half then also
// runs privileged. That is the trade for a single command; the two-role
// invocation is still there when the split matters.
//
// The first half to return ends the process: a UI with no agent behind it, or
// an agent with nothing serving it, is not worth staying up for.
func runLocal(uiAddr, agentAddr string) error {
	target, err := localTarget(agentAddr)
	if err != nil {
		return err
	}

	errc := make(chan error, 2)
	run := func(name string, fn func() error) {
		if err := fn(); err != nil {
			errc <- fmt.Errorf("%s: %w", name, err)
			return
		}
		// A clean return - agent.Run does this after a graceful stop on
		// SIGINT/SIGTERM, which is a normal exit, not a failure.
		errc <- nil
	}

	go run("agent", func() error { return agent.Run(agentAddr) })
	// No need to wait for the agent to be listening first: the UI dials it per
	// request, and reports a per-node error until it answers.
	go run("ui", func() error { return ui.Run(uiAddr, "", "local="+target) })

	return <-errc
}

// localTarget turns the agent's listen address into one the in-process UI can
// dial. A wildcard or missing host means "every interface", which is not a
// destination, so it becomes localhost - where the agent we just started is.
func localTarget(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("--agent-listen %q: %w", listen, err)
	}
	if port == "" {
		return "", fmt.Errorf("--agent-listen %q: no port", listen)
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "localhost"
	}
	return net.JoinHostPort(host, port), nil
}
