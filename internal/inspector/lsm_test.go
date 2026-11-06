package inspector

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestReadActiveLSMs covers both places the list is read from: the agent's own
// securityfs, and pid 1's when the agent's is not mounted - the DaemonSet case.
func TestReadActiveLSMs(t *testing.T) {
	procRoot, root := t.TempDir(), t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := readActiveLSMs(procRoot, root); err == nil {
		t.Fatal("no file anywhere: want an error, so the page can say the check did not run")
	}

	// The kernel writes no trailing newline; the list is the same either way.
	write(filepath.Join(procRoot, "1", "root", "sys", "kernel", "security", "lsm"), "lockdown,capability,yama,apparmor\n")
	got, err := readActiveLSMs(procRoot, root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"lockdown", "capability", "yama", "apparmor"}; !slices.Equal(got, want) {
		t.Errorf("through pid 1: got %q, want %q", got, want)
	}

	write(filepath.Join(root, "sys", "kernel", "security", "lsm"), "capability,bpf")
	got, err = readActiveLSMs(procRoot, root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"capability", "bpf"}; !slices.Equal(got, want) {
		t.Errorf("own securityfs: got %q, want %q", got, want)
	}
}
