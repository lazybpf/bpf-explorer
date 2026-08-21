package tracelog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTracefsMounts(t *testing.T) {
	mounts := `sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
debugfs /sys/kernel/debug debugfs rw,nosuid,nodev,noexec,relatime 0 0
tracefs /sys/kernel/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0
tracefs /sys/kernel/debug/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0
short line
`
	path := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(path, []byte(mounts), 0o644); err != nil {
		t.Fatal(err)
	}

	got := tracefsMounts(path)
	want := []string{"/sys/kernel/debug/tracing", "/sys/kernel/tracing", "/sys/kernel/debug/tracing"}
	if len(got) != len(want) {
		t.Fatalf("tracefsMounts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mount %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestTracefsMountsMissingFile covers a /proc/mounts that cannot be read: the
// well-known paths must still be tried.
func TestTracefsMountsMissingFile(t *testing.T) {
	if got := tracefsMounts(filepath.Join(t.TempDir(), "absent")); got != nil {
		t.Errorf("expected no mounts, got %v", got)
	}
	if got := candidates(filepath.Join(t.TempDir(), "absent")); len(got) != len(wellKnown) {
		t.Errorf("expected the well-known paths, got %v", got)
	}
}

func TestFindTracePipePrefersMountedTracefs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(path, []byte("tracefs /custom/tracing tracefs rw 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Both the mounted path and a well-known one are readable: the mount wins.
	readable := func(p string) bool {
		return p == "/custom/tracing/trace_pipe" || p == "/sys/kernel/tracing/trace_pipe"
	}
	got, err := findTracePipe(path, readable)
	if err != nil {
		t.Fatalf("findTracePipe: %v", err)
	}
	if want := "/custom/tracing/trace_pipe"; got != want {
		t.Errorf("findTracePipe = %q, want %q", got, want)
	}
}

func TestFindTracePipeFallsBackToWellKnown(t *testing.T) {
	only := "/sys/kernel/debug/tracing/trace_pipe"
	got, err := findTracePipe(filepath.Join(t.TempDir(), "absent"), func(p string) bool { return p == only })
	if err != nil {
		t.Fatalf("findTracePipe: %v", err)
	}
	if got != only {
		t.Errorf("findTracePipe = %q, want %q", got, only)
	}
}

// TestFindTracePipeNoneReadable checks the error names what was tried, since
// that is all an operator gets when tracefs is not visible to the agent.
func TestFindTracePipeNoneReadable(t *testing.T) {
	_, err := findTracePipe(filepath.Join(t.TempDir(), "absent"), func(string) bool { return false })
	if err == nil {
		t.Fatal("expected an error when nothing is readable")
	}
	for _, want := range []string{"/sys/kernel/tracing/trace_pipe", "/sys/kernel/debug/tracing/trace_pipe"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}
