// Package agent runs the per-node, read-only eBPF inspection gRPC server. It
// reads maps/programs via cilium/ebpf (internal/inspector). Reading BPF objects
// requires privileges (CAP_BPF/CAP_SYS_ADMIN); it runs in the privileged
// DaemonSet pod.
package agent

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
	"github.com/lazybpf/bpf-explorer/internal/inspector"
	"github.com/lazybpf/bpf-explorer/internal/server"
	"github.com/lazybpf/bpf-explorer/internal/tracelog"
	"google.golang.org/grpc"
)

// Run serves the gRPC inspection API on addr until SIGINT/SIGTERM.
func Run(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	// One trace_pipe hub per agent process: it is shared by every TraceLog
	// stream so the node's trace buffer has a single reader.
	pb.RegisterBpfInspectorServer(grpcServer, server.New(inspector.New(), tracelog.NewHub()))

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Printf("agent: shutting down")
		grpcServer.GracefulStop()
	}()

	log.Printf("agent: listening on %s", addr)
	return grpcServer.Serve(lis)
}
