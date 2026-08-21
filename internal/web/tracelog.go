package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// sseKeepalive bounds how long the stream stays silent. trace_pipe can be idle
// for minutes, and an idle connection is what proxies and port-forwards drop.
const sseKeepalive = 20 * time.Second

// sseLine is the payload of a trace-log event. JSON, because a trace line holds
// whatever bytes a program on the node printed: marshalling escapes any newline
// so one line stays one SSE `data:` field.
type sseLine struct {
	Line    string `json:"line"`
	Dropped uint64 `json:"dropped,omitempty"`
}

// sseGone is the payload of the terminal "gone" event, telling the page why the
// stream ended so it can stop instead of reconnecting into the same error.
type sseGone struct {
	Message string `json:"message"`
}

// tracelog renders the trace-log page; the lines arrive over SSE from
// tracelogStream.
func (h *Handlers) tracelog(w http.ResponseWriter, r *http.Request) {
	data := pageData{Node: r.PathValue("node"), Tab: "tracelog"}
	data.Nodes, _ = h.nodes()
	h.render(w, "tracelog", data)
}

// tracelogStream bridges the agent's TraceLog gRPC stream to Server-Sent Events.
// It runs for as long as the browser keeps the EventSource open, so unlike the
// page handlers it sets no request timeout. Closing the response ends the gRPC
// stream, which is what releases the node's trace_pipe.
func (h *Handlers) tracelogStream(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")

	conn, err := h.dial(node)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer conn.Close()

	stream, err := pb.NewBpfInspectorClient(conn).TraceLog(r.Context(), &pb.TraceLogRequest{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // no buffering proxy between us and the browser
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	rc.Flush()

	// Recv in its own goroutine so keepalives can go out while the pipe is
	// quiet. It ends with the request: the gRPC call is bound to r.Context().
	events := make(chan *pb.TraceLogEvent)
	errs := make(chan error, 1)
	go func() {
		for {
			ev, rerr := stream.Recv()
			if rerr != nil {
				errs <- rerr
				return
			}
			select {
			case events <- ev:
			case <-r.Context().Done():
				return
			}
		}
	}()

	tick := time.NewTicker(sseKeepalive)
	defer tick.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case rerr := <-errs:
			// The browser hanging up cancels the request first, so anything
			// here is the agent's side ending: report it and let the page stop.
			writeSSE(w, rc, "gone", sseGone{Message: rerr.Error()})
			return
		case ev := <-events:
			if err := writeSSE(w, rc, "", sseLine{Line: ev.GetLine(), Dropped: ev.GetDropped()}); err != nil {
				return
			}
		case <-tick.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}

// writeSSE writes one event and flushes it. An empty name sends the default
// "message" event, which EventSource delivers to onmessage.
func writeSSE(w io.Writer, rc *http.ResponseController, name string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if name != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", name); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
		return err
	}
	return rc.Flush()
}
