package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
	"google.golang.org/grpc/status"
)

// statsOn reports whether the node's kernel is counting program runs, by
// whoever turned that on. The programs page shows its stats columns only then:
// with counting off they hold stale totals or zeros.
func statsOn(st *pb.StatsState) bool {
	return st.GetHeld() || st.GetSysctl() || len(st.GetHolders()) > 0
}

// statsLocked reports whether stats are on for a reason the toggle cannot
// undo: the sysctl, or another process's fd. Turning the agent's own fd off
// would change nothing a reader can see.
func statsLocked(st *pb.StatsState) bool {
	return st.GetSysctl() || len(st.GetHolders()) > 0
}

// statsBy says who keeps stats on, for the locked toggle's tooltip.
func statsBy(st *pb.StatsState) string {
	var by []string
	if st.GetSysctl() {
		by = append(by, "kernel.bpf_stats_enabled=1")
	}
	for _, h := range st.GetHolders() {
		by = append(by, fmt.Sprintf("%s(%d)", h.GetComm(), h.GetPid()))
	}
	return strings.Join(by, ", ")
}

// statsOffIn is the countdown next to the toggle, in whole minutes rounded up
// so it never reads 0 while still on.
func statsOffIn(seconds uint32) string {
	return fmt.Sprintf("off in %d min", (seconds+59)/60)
}

// runTime formats a run time in nanoseconds with three significant digits in
// the largest unit that keeps it at or above 1: 512ns, 3.41µs, 12.0ms, 1.52s.
// Program runs are nanoseconds to microseconds each, so cpuTime's millisecond
// floor would show most averages as 0ms.
func runTime(ns uint64) string {
	units := []struct {
		name string
		size float64
	}{{"s", 1e9}, {"ms", 1e6}, {"µs", 1e3}}
	for _, u := range units {
		if float64(ns) >= u.size {
			v := float64(ns) / u.size
			prec := 2
			switch {
			case v >= 100:
				prec = 0
			case v >= 10:
				prec = 1
			}
			return strconv.FormatFloat(v, 'f', prec, 64) + u.name
		}
	}
	return strconv.FormatUint(ns, 10) + "ns"
}

// cpuPercent formats a program's share of one CPU, empty when the agent did
// not sample it. Two decimals below 10%, since most programs sit well under
// 1%; "<0.01%" rather than a 0 that would read as never running.
func cpuPercent(p *pb.ProgramInfo) string {
	if p.CpuPercent == nil {
		return ""
	}
	v := *p.CpuPercent
	switch {
	case v == 0:
		return "0%"
	case v < 0.01:
		return "<0.01%"
	case v < 10:
		return strconv.FormatFloat(v, 'f', 2, 64) + "%"
	case v < 100:
		return strconv.FormatFloat(v, 'f', 1, 64) + "%"
	}
	return strconv.FormatFloat(v, 'f', 0, 64) + "%"
}

// avgRun is a program's run time per run, empty when it has not run.
func avgRun(p *pb.ProgramInfo) string {
	if p.GetRunCount() == 0 {
		return ""
	}
	return runTime(p.GetRunTimeNs() / p.GetRunCount())
}

// setStats turns the node's stats switch on or off from the programs page's
// toggle, then sends the browser back to the list it came from. A failure is
// shown on that list rather than redirected away, so the reason is on screen.
func (h *Handlers) setStats(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	on := r.FormValue("on") == "1"
	back := url.Values{}
	if g := strings.TrimSpace(r.FormValue("loader")); g != "" {
		back.Set("loader", g)
	}

	err := func() error {
		conn, err := h.dial(node)
		if err != nil {
			return err
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		_, err = pb.NewBpfInspectorClient(conn).SetStats(ctx, &pb.SetStatsRequest{Enabled: on})
		return err
	}()

	r.URL.RawQuery = back.Encode()
	if err != nil {
		h.programList(w, r, status.Convert(err).Message())
		return
	}
	target := "/nodes/" + url.PathEscape(node) + "/programs"
	if q := r.URL.RawQuery; q != "" {
		target += "?" + q
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
