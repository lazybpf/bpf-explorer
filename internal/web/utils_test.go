package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUtilsRedirects covers the section's bare URL, which names no utility and
// so forwards to one. Links written before the utilities were separated arrive
// here too - one page took a pid and an inode together - and must land on the
// lookup they asked for rather than on whichever page happens to be first.
func TestUtilsRedirects(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	router := h.Router()

	tests := []struct{ name, from, want string }{
		{"bare path", "/nodes/node-a/utils", "/nodes/node-a/utils/pid"},
		{"old pid link", "/nodes/node-a/utils?pid=1234", "/nodes/node-a/utils/pid?pid=1234"},
		{"old inode link", "/nodes/node-a/utils?inode=42&dev=8%3a2", "/nodes/node-a/utils/inode?inode=42&dev=8%3a2"},
		{"old walk", "/nodes/node-a/utils?inode=42&root=%2Fsrv&walk=1", "/nodes/node-a/utils/inode?inode=42&root=%2Fsrv&walk=1"},
		// The old page carried the other lookup in a hidden field, so an empty
		// one says nothing about what was asked; a filled-in pid does.
		{"old link with both", "/nodes/node-a/utils?inode=&pid=1234", "/nodes/node-a/utils/pid?inode=&pid=1234"},
		{"old link asking both", "/nodes/node-a/utils?inode=42&pid=1234", "/nodes/node-a/utils/pid?inode=42&pid=1234"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.from, nil))
			if rec.Code != http.StatusFound {
				t.Errorf("GET %s = %d, want %d", tc.from, rec.Code, http.StatusFound)
			}
			if got := rec.Header().Get("Location"); got != tc.want {
				t.Errorf("GET %s redirected to %q, want %q", tc.from, got, tc.want)
			}
		})
	}
}

// TestUtilNav pins what separating the utilities bought: each page asks one
// question, and the others are a click away in the section's menu rather than a
// second form further down the same page.
func TestUtilNav(t *testing.T) {
	pid := renderUtil(t, "utilpid", pageData{Node: "node-a", Tab: "utils", Util: "pid"})
	inode := renderUtil(t, "utilinode", pageData{Node: "node-a", Tab: "utils", Util: "inode"})

	for _, tc := range []struct {
		page, out, own, other string
	}{
		{"utilpid", pid, "/nodes/node-a/utils/pid", "/nodes/node-a/utils/inode"},
		{"utilinode", inode, "/nodes/node-a/utils/inode", "/nodes/node-a/utils/pid"},
	} {
		// The tab bar says which section you are in, the menu under it which
		// utility you are on.
		if !strings.Contains(tc.out, `<a class="active" href="/nodes/node-a/utils">`) {
			t.Errorf("%s should mark the utils tab active\n%s", tc.page, tc.out)
		}
		if !strings.Contains(tc.out, `<a class="active" href="`+tc.own+`"`) {
			t.Errorf("%s should mark its own menu entry active\n%s", tc.page, tc.out)
		}
		if !strings.Contains(tc.out, `<a class="" href="`+tc.other+`"`) {
			t.Errorf("%s should offer the other utility, unmarked\n%s", tc.page, tc.out)
		}
	}

	// Neither page carries the other's form - that was the point of the split,
	// and the hidden fields that kept the two lookups in step went with it.
	if strings.Contains(pid, `name="inode"`) {
		t.Errorf("the inode lookup has its own page now\n%s", pid)
	}
	if strings.Contains(inode, `name="pid"`) {
		t.Errorf("the pid lookup has its own page now\n%s", inode)
	}

	// pid leads: it is the number a map dump hands you most often, and it is
	// where the bare /utils path lands.
	if i, j := strings.Index(pid, "/utils/pid"), strings.Index(pid, "/utils/inode"); i > j {
		t.Errorf("the pid utility should come first in the menu\n%s", pid)
	}
}

// TestUtilNavAcrossNodes: a utility is a question, not an object, so switching
// node keeps it - unlike a map dump, which cannot follow.
func TestUtilNavAcrossNodes(t *testing.T) {
	out := renderUtil(t, "utilinode", pageData{
		Node: "node-a", Nodes: []string{"node-a", "node-b"}, Tab: "utils", Util: "inode"})
	if !strings.Contains(out, `href="/nodes/node-b/utils/inode"`) {
		t.Errorf("the node picker should stay on the inode utility\n%s", out)
	}
}

func TestComma(t *testing.T) {
	for in, want := range map[uint64]string{
		0: "0", 7: "7", 999: "999", 1000: "1,000", 4120013: "4,120,013",
	} {
		if got := comma(in); got != want {
			t.Errorf("comma(%d) = %q, want %q", in, got, want)
		}
	}
}

func renderUtil(t *testing.T, page string, data pageData) string {
	t.Helper()
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.render(rec, page, data)
	return rec.Body.String()
}
