// Command bpf-explorer is a single binary that runs in one of two roles,
// selected with --role, so one image serves both the DaemonSet agent and the
// UI Deployment:
//
//	bpf-explorer --role=agent --listen=:50051
//	bpf-explorer --role=ui    --listen=:8080 --namespace=bpf-explorer
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/lazybpf/bpf-explorer/internal/agent"
	"github.com/lazybpf/bpf-explorer/internal/ui"
	"github.com/lazybpf/bpf-explorer/internal/version"
)

func main() {
	role := flag.String("role", "", "which component to run: agent | ui")
	listen := flag.String("listen", "", "listen address (agent default :50051, ui default :8080)")
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
	default:
		log.Fatalf("--role must be 'agent' or 'ui' (got %q)", *role)
	}
}
