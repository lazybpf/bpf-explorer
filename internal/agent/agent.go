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
	"time"

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
		// Hand the signal back to the runtime so a second Ctrl+C kills the
		// process outright, however wedged the first shutdown gets.
		signal.Stop(sig)
		log.Printf("agent: shutting down")
		stop(grpcServer, shutdownGrace)
	}()

	log.Printf("agent: listening on %s", addr)
	return grpcServer.Serve(lis)
}

// shutdownGrace bounds the wait for in-flight RPCs. Inspection calls answer in
// milliseconds, so this is really the deadline for the streams that never end
// on their own.
const shutdownGrace = 2 * time.Second

// stopper is the part of *grpc.Server that shutdown drives, so the giving-up
// can be tested without standing up a server.
type stopper interface {
	GracefulStop()
	Stop()
}

// stop lets in-flight RPCs finish, then cuts off whatever is left. A TraceLog
// stream runs until its client goes away, so GracefulStop alone waits on a
// browser tab that may never close - Ctrl+C looked like a hang, with the process
// still holding trace_pipe.
func stop(srv stopper, grace time.Duration) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(grace):
		log.Printf("agent: %s grace expired, dropping open streams", grace)
		// Deliberately not waiting on done afterwards: Stop cuts the
		// connections, and shutdown must not be able to block twice.
		srv.Stop()
	}
}
