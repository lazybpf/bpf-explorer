package version

import "testing"

func TestInfoString(t *testing.T) {
	tests := []struct {
		name string
		in   Info
		want string
	}{
		{"released", Info{Version: "v0.1.0", Commit: "0dd5b51"}, "v0.1.0 (0dd5b51)"},
		{"dirty dev tree", Info{Version: "dev", Commit: "0dd5b51", Dirty: true}, "dev (0dd5b51-dirty)"},
		{"no vcs stamp", Info{Version: "dev", Commit: "unknown"}, "dev (unknown)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Get must always produce something displayable, even with nothing stamped in.
func TestGetFallsBackToPlaceholders(t *testing.T) {
	got := Get()
	if got.Version == "" {
		t.Error("Version is empty; want a value (\"dev\" when unstamped)")
	}
	if got.Commit == "" {
		t.Error("Commit is empty; want a short SHA or \"unknown\"")
	}
	if len(got.Commit) > shortSHALen && got.Commit != "unknown" {
		t.Errorf("Commit = %q; want it truncated to %d chars", got.Commit, shortSHALen)
	}
}

// A link-time Version must win over the VCS stamp.
func TestLinkTimeVersionWins(t *testing.T) {
	Version, Commit = "v9.9.9", "abcdef1234567890"
	t.Cleanup(func() { Version, Commit = "", "" })

	got := Get()
	if got.Version != "v9.9.9" {
		t.Errorf("Version = %q, want v9.9.9", got.Version)
	}
	if got.Commit != "abcdef1" {
		t.Errorf("Commit = %q, want abcdef1 (truncated)", got.Commit)
	}
}
