package web

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

func TestCheckLSM(t *testing.T) {
	lsmProgs := []*pb.ProgramInfo{
		{Id: 1, Name: "file_open", Type: "LSM"},
		{Id: 2, Name: "bprm_check", Type: "LSM"},
		{Id: 3, Name: "trace_conn", Type: "Tracing"},
	}
	noBPF := []string{"lockdown", "capability", "yama", "apparmor"}

	for _, tc := range []struct {
		name  string
		progs []*pb.ProgramInfo
		lsms  []string
		note  string
		want  *lsmWarning
	}{
		{"bpf lsm off", lsmProgs, noBPF, "", &lsmWarning{Programs: 2, Active: "lockdown,capability,yama,apparmor"}},
		{"bpf lsm on", lsmProgs, append(noBPF, "bpf"), "", nil},
		{"no lsm programs", lsmProgs[2:], noBPF, "", nil},
		{"list unreadable", lsmProgs, nil, "permission denied", &lsmWarning{Programs: 2, Note: "permission denied"}},
		{"agent too old to send it", lsmProgs, nil, "", nil},
	} {
		got := checkLSM(tc.progs, tc.lsms, tc.note)
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestProgramsLSMWarningRender(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	render := func(w *lsmWarning) string {
		t.Helper()
		data := pageData{
			Node:     "node-a",
			Tab:      "programs",
			Programs: []*pb.ProgramInfo{{Id: 1, Name: "file_open", Type: "LSM"}},
			LSMWarn:  w,
		}
		var buf bytes.Buffer
		if err := h.pages["programs"].ExecuteTemplate(&buf, "layout", data); err != nil {
			t.Fatalf("execute: %v", err)
		}
		return buf.String()
	}

	out := render(&lsmWarning{Programs: 1, Active: "capability,apparmor"})
	if !strings.Contains(out, `<p class="warn">1 LSM program never runs`) || !strings.Contains(out, "<code>capability,apparmor</code>") {
		t.Errorf("expected the warning naming the active LSMs\n%s", out)
	}
	if out := render(&lsmWarning{Programs: 3, Active: "capability"}); !strings.Contains(out, "3 LSM programs never run") {
		t.Errorf("expected the plural\n%s", out)
	}
	if out := render(&lsmWarning{Programs: 1, Note: "permission denied"}); strings.Contains(out, `class="warn"`) || !strings.Contains(out, "permission denied") {
		t.Errorf("expected an unreadable list to say the check did not run, not warn\n%s", out)
	}
	if out := render(nil); strings.Contains(out, "LSM program") {
		t.Errorf("expected nothing without a warning\n%s", out)
	}
}
