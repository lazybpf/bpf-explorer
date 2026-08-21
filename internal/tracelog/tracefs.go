// Package tracelog streams the kernel tracing pipe (tracefs trace_pipe), the
// same source as `bpftool prog tracelog` and where bpf_trace_printk() output
// lands.
//
// Unlike internal/inspector, reading trace_pipe is not a pure read: a node has
// one global trace buffer and whoever reads it drains it, so every line handed
// out here is gone for any other reader on that node. Hub therefore keeps at
// most one reader open, shared by all clients, and only while a client is
// attached.
package tracelog

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// wellKnown lists the usual tracefs mount points, tried in the order bpftool
// tries them when /proc/self/mounts names none.
var wellKnown = []string{
	"/sys/kernel/tracing",
	"/sys/kernel/debug/tracing",
	"/tracing",
	"/trace",
}

// FindTracePipe returns the path of the trace_pipe to read, preferring a tracefs
// mount listed in /proc/self/mounts. It never mounts anything: an agent that
// cannot see tracefs gets an error naming what was tried.
func FindTracePipe() (string, error) {
	return findTracePipe("/proc/self/mounts", readable)
}

func findTracePipe(mountsPath string, readable func(string) bool) (string, error) {
	candidates := candidates(mountsPath)
	for _, p := range candidates {
		if readable(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("no readable trace_pipe (tried %s): is tracefs mounted and visible to the agent?",
		strings.Join(candidates, ", "))
}

// candidates returns the trace_pipe paths to try, mounted tracefs first, then
// the well-known locations, without duplicates.
func candidates(mountsPath string) []string {
	seen := map[string]bool{}
	var out []string
	for _, dir := range append(tracefsMounts(mountsPath), wellKnown...) {
		if seen[dir] {
			continue
		}
		seen[dir] = true
		out = append(out, filepath.Join(dir, "trace_pipe"))
	}
	return out
}

// tracefsMounts returns the tracefs mount points listed in a /proc/mounts-style
// file. A debugfs mount contributes its "tracing" subdirectory, which is where
// tracefs is mounted on nodes that only expose it under debugfs. An unreadable
// file yields no mounts; the well-known paths still get tried.
func tracefsMounts(mountsPath string) []string {
	f, err := os.Open(mountsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		mnt, fstype := fields[1], fields[2]
		switch fstype {
		case "tracefs":
			out = append(out, mnt)
		case "debugfs":
			out = append(out, filepath.Join(mnt, "tracing"))
		}
	}
	return out
}

// readable reports whether path can be opened for reading. trace_pipe blocks on
// read but not on open, so this does not consume anything.
func readable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
