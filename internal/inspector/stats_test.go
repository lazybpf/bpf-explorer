package inspector

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeStatsFD stands in for a BPF_ENABLE_STATS fd, counting how many are open.
type fakeStatsFD struct{ open *int }

func (f fakeStatsFD) Close() error { *f.open--; return nil }

func testSwitch(t *testing.T, ttl time.Duration) (*StatsSwitch, *int) {
	t.Helper()
	open := 0
	s := NewStatsSwitch()
	s.ttl = ttl
	s.procRoot = t.TempDir()
	s.enable = func() (io.Closer, error) {
		open++
		return fakeStatsFD{&open}, nil
	}
	return s, &open
}

func TestStatsSwitchOnOff(t *testing.T) {
	s, open := testSwitch(t, time.Minute)
	st, err := s.Set(true)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Held || *open != 1 {
		t.Fatalf("after on: held=%v open=%d", st.Held, *open)
	}
	if st.Left <= 0 || st.Left > time.Minute {
		t.Errorf("Left = %v, want within the ttl", st.Left)
	}

	// On again restarts the countdown on the same fd, not a second one.
	if _, err := s.Set(true); err != nil {
		t.Fatal(err)
	}
	if *open != 1 {
		t.Errorf("on twice opened %d fds, want 1", *open)
	}

	st, err = s.Set(false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Held || *open != 0 {
		t.Errorf("after off: held=%v open=%d", st.Held, *open)
	}
	// Off while off is not an error.
	if _, err := s.Set(false); err != nil {
		t.Errorf("off twice: %v", err)
	}
}

func TestStatsSwitchTurnsItselfOff(t *testing.T) {
	s, open := testSwitch(t, 20*time.Millisecond)
	if _, err := s.Set(true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.State().Held {
		if time.Now().After(deadline) {
			t.Fatal("still held after the ttl")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if *open != 0 {
		t.Errorf("fd left open after the ttl: %d", *open)
	}
}

// A countdown armed for one hold must not close the next one: off, then on
// again, before the first timer would have fired.
func TestStatsSwitchStaleTimer(t *testing.T) {
	s, open := testSwitch(t, 50*time.Millisecond)
	if _, err := s.Set(true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(false); err != nil {
		t.Fatal(err)
	}
	s.ttl = time.Hour
	if _, err := s.Set(true); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if !s.State().Held || *open != 1 {
		t.Errorf("the first hold's timer dropped the second: open=%d", *open)
	}
	s.Set(false)
}

func TestStatsSwitchEnableError(t *testing.T) {
	s, _ := testSwitch(t, time.Minute)
	s.enable = func() (io.Closer, error) { return nil, errors.New("invalid argument") }
	st, err := s.Set(true)
	if err == nil || st.Held {
		t.Errorf("a kernel refusal must surface and hold nothing: err=%v held=%v", err, st.Held)
	}
}

func TestReadStatsSysctl(t *testing.T) {
	root := t.TempDir()
	if readStatsSysctl(root) {
		t.Error("a missing sysctl (before 5.1) must read as off")
	}
	dir := filepath.Join(root, "sys/kernel")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]bool{"0\n": false, "1\n": true} {
		if err := os.WriteFile(filepath.Join(dir, "bpf_stats_enabled"), []byte(in), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := readStatsSysctl(root); got != want {
			t.Errorf("sysctl %q: got %v, want %v", in, got, want)
		}
	}
}

func TestScanStatsHolders(t *testing.T) {
	root := t.TempDir()
	writeProcEntry(t, root, "100", "bpftop", map[string][2]string{
		"3": {"anon_inode:bpf-prog", "prog_id:\t1\n"},
		"4": {bpfStatsLink, ""},
		"5": {bpfStatsLink, ""}, // a second fd, same process: listed once
	})
	writeProcEntry(t, root, "200", "loader", map[string][2]string{
		"3": {"anon_inode:bpf-prog", "prog_id:\t1\n"},
	})
	writeProcEntry(t, root, "300", "bpf-explorer", map[string][2]string{
		"7": {bpfStatsLink, ""},
	})

	got := scanStatsHolders(root, 300)
	if len(got) != 1 || got[0] != (ProcessRef{PID: 100, Comm: "bpftop"}) {
		t.Errorf("holders = %+v, want only bpftop(100): not the loader, not self", got)
	}
}

func TestCPUShare(t *testing.T) {
	t0 := time.Unix(1000, 0)
	read := func(rt time.Duration, after time.Duration) runTimeRead { return runTimeRead{rt, t0.Add(after)} }
	for name, c := range map[string]struct {
		before, after runTimeRead
		want          float64
		ok            bool
	}{
		"idle":             {read(5*time.Second, 0), read(5*time.Second, time.Second), 0, true},
		"a tenth of a CPU": {read(0, 0), read(100*time.Millisecond, time.Second), 10, true},
		"two CPUs":         {read(time.Second, 0), read(5*time.Second, 2*time.Second), 200, true},
		// Same id, run time went backwards: the program was replaced.
		"recycled id":  {read(time.Second, 0), read(time.Millisecond, time.Second), 0, false},
		"no wall time": {read(0, 0), read(time.Millisecond, 0), 0, false},
	} {
		got, ok := cpuShare(c.before, c.after)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: cpuShare = %v, %v; want %v, %v", name, got, ok, c.want, c.ok)
		}
	}
}
