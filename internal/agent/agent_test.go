package agent

import (
	"sync"
	"testing"
	"time"
)

// fakeServer stands in for a *grpc.Server. GracefulStop blocks until released,
// which is what an open TraceLog stream does to the real one.
type fakeServer struct {
	released chan struct{}

	mu   sync.Mutex
	hard bool
}

func (f *fakeServer) GracefulStop() { <-f.released }

func (f *fakeServer) Stop() {
	f.mu.Lock()
	f.hard = true
	f.mu.Unlock()
	close(f.released) // a real Stop cuts the connections, freeing GracefulStop
}

func (f *fakeServer) hardStopped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hard
}

// TestStopCutsOffHungStreams is the Ctrl+C hang: a TraceLog stream keeps
// GracefulStop waiting for as long as the browser stays connected, so shutdown
// has to give up and cut it off rather than sit on trace_pipe forever.
func TestStopCutsOffHungStreams(t *testing.T) {
	srv := &fakeServer{released: make(chan struct{})}

	done := make(chan struct{})
	go func() {
		stop(srv, 10*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop never returned; Ctrl+C would hang")
	}
	if !srv.hardStopped() {
		t.Error("grace expired without a hard Stop")
	}
}

// TestStopWaitsForGraceful checks the grace is a deadline, not a delay: with
// nothing in flight, shutdown finishes at once and never cuts anything off.
func TestStopWaitsForGraceful(t *testing.T) {
	srv := &fakeServer{released: make(chan struct{})}
	close(srv.released) // GracefulStop returns immediately

	stop(srv, time.Minute) // would outlast the test if the grace were a sleep

	if srv.hardStopped() {
		t.Error("Stop called even though GracefulStop returned in time")
	}
}
