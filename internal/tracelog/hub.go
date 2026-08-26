package tracelog

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
)

// defaultBuffer is how many lines a subscriber may fall behind before lines are
// dropped for it. trace_pipe can burst far faster than a browser renders, and a
// slow client must never stall the shared reader.
const defaultBuffer = 1024

// Event is one trace_pipe line delivered to a subscriber.
type Event struct {
	Line string
	// Dropped counts the lines this subscriber missed - its buffer was full -
	// between the previous event and this one.
	Dropped uint64
}

// Hub fans one trace_pipe reader out to every attached subscriber. The reader
// opens when the first subscriber attaches and closes when the last one leaves,
// so the agent never drains the node's trace buffer while nobody is watching.
type Hub struct {
	// open resolves and opens the trace pipe. nil means openTracePipe; tests
	// substitute their own.
	open func(context.Context) (io.ReadCloser, string, error)
	// buffer overrides defaultBuffer in tests.
	buffer int

	mu     sync.Mutex
	subs   map[uint64]*Subscription
	nextID uint64
	stop   context.CancelFunc // cancels the running reader; nil when none runs
	gen    uint64             // reader generation, so a stale reader's exit cannot tear down its successor
}

func NewHub() *Hub { return &Hub{} }

// Subscription is one client's view of the shared pipe.
type Subscription struct {
	hub     *Hub
	id      uint64
	ch      chan Event
	dropped uint64 // guarded by hub.mu
}

// Events yields the subscriber's lines. It is closed when the shared reader
// stops on its own (pipe error), so a client can tell that apart from its own
// Close.
func (s *Subscription) Events() <-chan Event { return s.ch }

// Close detaches the subscriber, stopping the shared reader if it was the last.
func (s *Subscription) Close() { s.hub.unsubscribe(s.id) }

// Subscribe attaches a client, starting the reader if it is the first. Opening
// the pipe happens here rather than in the reader goroutine so a missing tracefs
// or a permission error is returned to the caller instead of being logged.
func (h *Hub) Subscribe() (*Subscription, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.subs == nil {
		h.subs = map[uint64]*Subscription{}
	}
	if h.stop == nil {
		open := h.open
		if open == nil {
			open = openTracePipe
		}
		ctx, cancel := context.WithCancel(context.Background())
		rc, path, err := open(ctx)
		if err != nil {
			cancel()
			return nil, err
		}
		h.stop = cancel
		h.gen++
		log.Printf("tracelog: streaming %s", path)
		go h.read(rc, h.gen)
	}

	h.nextID++
	s := &Subscription{hub: h, id: h.nextID, ch: make(chan Event, h.bufferSize())}
	h.subs[s.id] = s
	return s, nil
}

func (h *Hub) bufferSize() int {
	if h.buffer > 0 {
		return h.buffer
	}
	return defaultBuffer
}

func (h *Hub) unsubscribe(id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	s, ok := h.subs[id]
	if !ok {
		return
	}
	delete(h.subs, id)
	// Safe: broadcast only sends while holding h.mu.
	close(s.ch)

	if len(h.subs) == 0 && h.stop != nil {
		log.Printf("tracelog: last client left, closing trace_pipe")
		h.stop()
		h.stop = nil
	}
}

// read scans the pipe line by line until it is cancelled or fails. Blank lines
// never reach a subscriber: they turn up in trace_pipe output between records
// and carry nothing - a real line always has a task, a cpu, a timestamp and a
// message. Dropping them here rather than in each client keeps them out of every
// stream, and off the wire.
func (h *Hub) read(rc io.ReadCloser, gen uint64) {
	defer rc.Close()

	sc := bufio.NewScanner(rc)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		h.broadcast(line)
	}
	h.readerDone(gen, sc.Err())
}

func (h *Hub) broadcast(line string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, s := range h.subs {
		select {
		case s.ch <- Event{Line: line, Dropped: s.dropped}:
			s.dropped = 0
		default:
			s.dropped++
		}
	}
}

// readerDone tears down the subscribers of a reader that stopped by itself, so
// each client learns the stream ended. A reader that has already been superseded
// (its generation is stale) touches nothing.
func (h *Hub) readerDone(gen uint64, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.gen != gen {
		return
	}
	if h.stop != nil {
		h.stop()
		h.stop = nil
	}
	for id, s := range h.subs {
		close(s.ch)
		delete(h.subs, id)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("tracelog: reader stopped: %v", err)
	}
}
