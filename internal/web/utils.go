package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The utils tab is a section, not a page: each utility answers one question
// about a node and gets its own URL under /nodes/{node}/utils/, its own handler
// and its own template. They share the tab, the sub-menu in partials.html and
// nothing else, so a lookup added later cannot disturb the ones already there.

// utils sends the section's bare URL on to a utility. Links written before the
// split land here too - one page took a pid and an inode together - so the query
// says which lookup was meant rather than being dropped on the way.
func (h *Handlers) utils(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// The node page is the default: it is the one utility that answers without
	// being asked a number first, so a bare click lands on something to read
	// rather than on an empty form.
	util := "node"
	switch {
	// A number names the lookup outright. The old page carried the pid as the
	// lookup and the inode in a hidden field, so a filled-in pid wins over an
	// inode that came along with it.
	case strings.TrimSpace(q.Get("pid")) != "":
		util = "pid"
	case strings.TrimSpace(q.Get("inode")) != "":
		util = "inode"
	// A form submitted empty carries its field without a number, which still
	// says which lookup was meant.
	case q.Has("pid"):
		util = "pid"
	case q.Has("inode"):
		util = "inode"
	}
	target := "/nodes/" + url.PathEscape(r.PathValue("node")) + "/utils/" + util
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// comma groups a count in threes. A walk over a real filesystem reports numbers
// in the millions, and 4120013 is not a number anyone reads at a glance.
func comma(n uint64) string {
	s := strconv.FormatUint(n, 10)
	var b strings.Builder
	for i, digit := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(digit)
	}
	return b.String()
}
