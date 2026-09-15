package web

import (
	"strings"
	"testing"
	"time"
)

func TestAgeOneUnit(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{45 * time.Second, "45s"},
		// The boundary rounds down to the coarser unit rather than to "60s".
		{time.Minute, "1m"},
		{90 * time.Second, "1m"},
		{59 * time.Minute, "59m"},
		{time.Hour, "1h"},
		{25 * time.Hour, "1d"},
		{9 * 24 * time.Hour, "9d"},
		// Clock skew between the node that dated the load and this process.
		{-3 * time.Second, "0s"},
	}
	for _, c := range cases {
		if got := age(c.d); got != c.want {
			t.Errorf("age(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestLoadedAt(t *testing.T) {
	// A kernel too old to report one, which the agent sends as no time at all
	// rather than as the epoch.
	if got := loadedAt(0); got != nil {
		t.Errorf("loadedAt(0) = %+v, want nil so the template can say so", got)
	}

	when := time.Now().Add(-2 * time.Hour)
	got := loadedAt(when.UnixNano())
	if got == nil {
		t.Fatal("loadedAt dropped a time the node did report")
	}
	if got.Ago != "2h" {
		t.Errorf("Ago = %q, want 2h", got.Ago)
	}
	// The timestamp carries its UTC offset: the tooltip is read against
	// `bpftool prog show` on a node that need not share this process's zone.
	if want := when.Format("2006-01-02T15:04:05-0700"); got.At != want {
		t.Errorf("At = %q, want %q", got.At, want)
	}
	if !strings.Contains(got.At, "T") {
		t.Errorf("At = %q, want the ISO form bpftool prints", got.At)
	}
}
