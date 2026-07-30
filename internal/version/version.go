// Package version reports which build of bpf-explorer is running.
//
// Released images stamp the values in at link time (see the Dockerfile):
//
//	go build -ldflags="-X github.com/lazybpf/bpf-explorer/internal/version.Version=v0.1.0 \
//	                   -X github.com/lazybpf/bpf-explorer/internal/version.Commit=<sha>"
//
// A plain `go build` stamps nothing, so we fall back to the VCS metadata the Go
// toolchain records in the binary - that keeps the UI honest for dev builds
// without anyone having to remember the -ldflags incantation.
package version

import "runtime/debug"

var (
	// Version is the release tag (e.g. "v0.1.0"), injected at link time.
	Version string
	// Commit is the full git SHA-1, injected at link time.
	Commit string
)

// shortSHALen is how much of the SHA-1 we show; enough to be unambiguous, short
// enough to sit in a page header.
const shortSHALen = 7

// Info describes the running build.
type Info struct {
	Version string // release tag, or "dev" when unstamped
	Commit  string // short SHA-1, or "unknown"
	Dirty   bool   // built from a tree with uncommitted changes
}

// Get returns the running build's version, preferring link-time values and
// falling back to the toolchain's VCS stamp.
func Get() Info {
	info := Info{Version: Version, Commit: Commit}

	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.modified":
				info.Dirty = s.Value == "true"
			}
		}
	}

	if info.Version == "" {
		info.Version = "dev"
	}
	if len(info.Commit) > shortSHALen {
		info.Commit = info.Commit[:shortSHALen]
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	return info
}

// String renders the build as "v0.1.0 (0dd5b51)", suffixing "-dirty" when the
// working tree had uncommitted changes.
func (i Info) String() string {
	s := i.Version + " (" + i.Commit
	if i.Dirty {
		s += "-dirty"
	}
	return s + ")"
}

// String is the package-level shorthand used by the UI templates.
func String() string { return Get().String() }
