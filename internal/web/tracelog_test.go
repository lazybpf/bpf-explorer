package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTracelogPage verifies the page points its EventSource at the node's own
// stream endpoint and keeps the draining warning visible.
func TestTracelogPage(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var buf bytes.Buffer
	data := pageData{Node: "node-a", Tab: "tracelog", Nodes: []string{"node-a", "node-b"}}
	if err := h.pages["tracelog"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		`data-stream="/nodes/node-a/tracelog/stream"`,
		`href="/nodes/node-a/tracelog"`, // the tab, active on this page
		`href="/nodes/node-b/tracelog"`, // switching nodes stays on the tab
		"drains it",
		"Newest line first.", // the listing grows upwards; say so on the page
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q\n%s", want, out)
		}
	}
}

// TestWriteSSE checks the framing a trace line has to survive: arbitrary bytes
// from the node must stay on a single `data:` field, or the browser would read
// one line as several events.
func TestWriteSSE(t *testing.T) {
	rec := httptest.NewRecorder()
	rc := http.NewResponseController(rec)

	if err := writeSSE(rec, rc, "", sseLine{Line: "bpf_trace_printk: a\nb\r\ndone \"q\"", Dropped: 4}); err != nil {
		t.Fatalf("writeSSE: %v", err)
	}
	got := rec.Body.String()

	want := "data: {\"line\":\"bpf_trace_printk: a\\nb\\r\\ndone \\\"q\\\"\",\"dropped\":4}\n\n"
	if got != want {
		t.Errorf("writeSSE wrote\n%q\nwant\n%q", got, want)
	}
	if !rec.Flushed {
		t.Error("event was not flushed; the browser would see it late or not at all")
	}
}

func TestWriteSSENamedEvent(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := writeSSE(rec, http.NewResponseController(rec), "gone", sseGone{Message: "unavailable"}); err != nil {
		t.Fatalf("writeSSE: %v", err)
	}
	if want := "event: gone\ndata: {\"message\":\"unavailable\"}\n\n"; rec.Body.String() != want {
		t.Errorf("writeSSE wrote %q, want %q", rec.Body.String(), want)
	}
}
