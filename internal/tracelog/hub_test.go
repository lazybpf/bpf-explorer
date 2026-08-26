package tracelog

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// fakePipe stands in for tracefs trace_pipe: reads block until a line is pushed
// or the reader's context is cancelled, as the poll-based pipeReader does.
type fakePipe struct {
	ctx   context.Context
	lines chan string
	buf   []byte

	closeOnce sync.Once
	closed    chan struct{}
}

func newFakePipe(ctx context.Context) *fakePipe {
	return &fakePipe{ctx: ctx, lines: make(chan string), closed: make(chan struct{})}
}

func (f *fakePipe) Read(b []byte) (int, error) {
	for len(f.buf) == 0 {
		select {
		case <-f.ctx.Done():
			return 0, f.ctx.Err()
		case line, ok := <-f.lines:
			if !ok {
				return 0, io.EOF
			}
			f.buf = []byte(line + "\n")
		}
	}
	n := copy(b, f.buf)
	f.buf = f.buf[n:]
	return n, nil
}

func (f *fakePipe) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

// fakeOpener records how many pipes the hub opened and hands back the last one.
type fakeOpener struct {
	mu    sync.Mutex
	opens int
	last  *fakePipe
	err   error
}

func (o *fakeOpener) open(ctx context.Context) (io.ReadCloser, string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.err != nil {
		return nil, "", o.err
	}
	o.opens++
	o.last = newFakePipe(ctx)
	return o.last, "/fake/trace_pipe", nil
}

func (o *fakeOpener) pipe(t *testing.T) *fakePipe {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.last == nil {
		t.Fatal("no pipe opened")
	}
	return o.last
}

func (o *fakeOpener) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.opens
}

func recvEvent(t *testing.T, s *Subscription) Event {
	t.Helper()
	select {
	case ev, ok := <-s.Events():
		if !ok {
			t.Fatal("subscription closed while waiting for a line")
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a line")
		return Event{}
	}
}

// TestHubFanOut checks every attached client sees every line, from one reader.
func TestHubFanOut(t *testing.T) {
	o := &fakeOpener{}
	h := &Hub{open: o.open}

	a, err := h.Subscribe()
	if err != nil {
		t.Fatalf("subscribe a: %v", err)
	}
	defer a.Close()
	b, err := h.Subscribe()
	if err != nil {
		t.Fatalf("subscribe b: %v", err)
	}
	defer b.Close()

	if got := o.count(); got != 1 {
		t.Fatalf("opened %d pipes, want 1 shared reader", got)
	}

	o.pipe(t).lines <- "hello from bpf_trace_printk"
	for name, sub := range map[string]*Subscription{"a": a, "b": b} {
		if ev := recvEvent(t, sub); ev.Line != "hello from bpf_trace_printk" {
			t.Errorf("subscriber %s got %q", name, ev.Line)
		}
	}
}

// TestHubSkipsBlankLines checks the empties trace_pipe emits between records do
// not become events: in the web view they rendered as a stream of bare
// timestamps, one blank row per real line.
func TestHubSkipsBlankLines(t *testing.T) {
	o := &fakeOpener{}
	h := &Hub{open: o.open}

	sub, err := h.Subscribe()
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()

	p := o.pipe(t)
	for _, line := range []string{"", "   ", "\t", "real line"} {
		p.lines <- line
	}
	if ev := recvEvent(t, sub); ev.Line != "real line" {
		t.Errorf("got %q, want the blanks skipped and %q delivered", ev.Line, "real line")
	}
}

// TestHubClosesPipeWithLastSubscriber is the behaviour that keeps the agent from
// draining the node's trace buffer when nobody is watching.
func TestHubClosesPipeWithLastSubscriber(t *testing.T) {
	o := &fakeOpener{}
	h := &Hub{open: o.open}

	a, err := h.Subscribe()
	if err != nil {
		t.Fatalf("subscribe a: %v", err)
	}
	b, err := h.Subscribe()
	if err != nil {
		t.Fatalf("subscribe b: %v", err)
	}
	pipe := o.pipe(t)

	a.Close()
	select {
	case <-pipe.closed:
		t.Fatal("pipe closed while a subscriber was still attached")
	case <-time.After(50 * time.Millisecond):
	}

	b.Close()
	select {
	case <-pipe.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe not closed after the last subscriber left")
	}

	// A later client gets a fresh reader.
	c, err := h.Subscribe()
	if err != nil {
		t.Fatalf("resubscribe: %v", err)
	}
	defer c.Close()
	if got := o.count(); got != 2 {
		t.Errorf("opened %d pipes, want a second one for the new client", got)
	}
	o.pipe(t).lines <- "second reader"
	if ev := recvEvent(t, c); ev.Line != "second reader" {
		t.Errorf("got %q, want the line from the new reader", ev.Line)
	}
}

// TestHubSubscribeError surfaces a missing/unreadable tracefs to the caller
// rather than logging it in a goroutine.
func TestHubSubscribeError(t *testing.T) {
	want := errors.New("no readable trace_pipe")
	h := &Hub{open: (&fakeOpener{err: want}).open}

	if _, err := h.Subscribe(); !errors.Is(err, want) {
		t.Fatalf("Subscribe error = %v, want %v", err, want)
	}
	// The failed attempt must not leave a reader half-started.
	if _, err := h.Subscribe(); !errors.Is(err, want) {
		t.Fatalf("second Subscribe error = %v, want %v", err, want)
	}
}

// TestHubDropsForSlowSubscriber verifies a client that falls behind loses lines
// and is told how many, instead of stalling the shared reader.
func TestHubDropsForSlowSubscriber(t *testing.T) {
	o := &fakeOpener{}
	h := &Hub{open: o.open, buffer: 2}

	s, err := h.Subscribe()
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer s.Close()
	pipe := o.pipe(t)

	// Two lines fit the buffer; the next three are dropped.
	for _, line := range []string{"one", "two", "three", "four", "five"} {
		pipe.lines <- line
	}
	for _, want := range []string{"one", "two"} {
		ev := recvEvent(t, s)
		if ev.Line != want || ev.Dropped != 0 {
			t.Fatalf("got (%q, dropped %d), want (%q, dropped 0)", ev.Line, ev.Dropped, want)
		}
	}

	// Reading freed the buffer, so the next line lands - carrying the count of
	// what was missed. Sending it also proves lines three..five were processed:
	// the reader takes it only after broadcasting them.
	pipe.lines <- "six"
	ev := recvEvent(t, s)
	if ev.Line != "six" || ev.Dropped != 3 {
		t.Errorf("got (%q, dropped %d), want (\"six\", dropped 3)", ev.Line, ev.Dropped)
	}
}

// TestHubReaderErrorClosesSubscribers checks a reader that dies on its own tells
// its clients, so the UI can say the stream ended.
func TestHubReaderErrorClosesSubscribers(t *testing.T) {
	o := &fakeOpener{}
	h := &Hub{open: o.open}

	s, err := h.Subscribe()
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer s.Close()

	close(o.pipe(t).lines) // pipe hits EOF
	select {
	case _, ok := <-s.Events():
		if ok {
			t.Fatal("expected the subscription channel to be closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the subscription to close")
	}
}
