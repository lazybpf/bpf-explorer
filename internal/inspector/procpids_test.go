package inspector

import (
	"os"
	"path/filepath"
	"testing"
)

// writeProcEntry lays out a fake /proc/<pid> with the given fds. Each fd is
// (link target, fdinfo contents); a symlink and matching fdinfo file are created.
func writeProcEntry(t *testing.T, root, pid, comm string, fds map[string][2]string) {
	t.Helper()
	procDir := filepath.Join(root, pid)
	if err := os.MkdirAll(filepath.Join(procDir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(procDir, "fdinfo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for fd, v := range fds {
		if err := os.Symlink(v[0], filepath.Join(procDir, "fd", fd)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(procDir, "fdinfo", fd), []byte(v[1]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScanProgramPIDs(t *testing.T) {
	root := t.TempDir()

	progFdinfo := "pos:\t0\nflags:\t02000002\nprog_type:\t26\nprog_id:\t42\n"
	otherProgFdinfo := "pos:\t0\nprog_id:\t7\n"
	mapFdinfo := "pos:\t0\nmap_type:\t1\nmap_id:\t99\n"

	// loader: holds prog 42 (twice -> deduped) and a map fd (ignored).
	writeProcEntry(t, root, "1000", "loader", map[string][2]string{
		"3": {"anon_inode:bpf-prog", progFdinfo},
		"4": {"anon_inode:bpf-prog", progFdinfo},
		"5": {"anon_inode:bpf-map", mapFdinfo},
		"6": {"/dev/null", ""},
	})
	// agent: also holds prog 42, plus prog 7.
	writeProcEntry(t, root, "1001", "agent", map[string][2]string{
		"3": {"anon_inode:bpf-prog", progFdinfo},
		"7": {"anon_inode:bpf-prog", otherProgFdinfo},
	})
	// non-pid dir must be ignored.
	if err := os.MkdirAll(filepath.Join(root, "sys"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := scanProgramPIDs(root)

	if len(got[42]) != 2 {
		t.Fatalf("prog 42: want 2 holders, got %d (%+v)", len(got[42]), got[42])
	}
	pids := map[uint32]string{}
	for _, r := range got[42] {
		pids[r.PID] = r.Comm
	}
	if pids[1000] != "loader" || pids[1001] != "agent" {
		t.Errorf("prog 42 holders = %+v, want loader(1000) and agent(1001)", got[42])
	}
	if len(got[7]) != 1 || got[7][0].PID != 1001 {
		t.Errorf("prog 7 holders = %+v, want just agent(1001)", got[7])
	}
	if _, ok := got[99]; ok {
		t.Errorf("map id 99 must not appear among program holders")
	}
}

func TestScanMapPIDs(t *testing.T) {
	root := t.TempDir()

	mapFdinfo := "pos:\t0\nflags:\t02000002\nmap_type:\t1\nkey_size:\t4\nvalue_size:\t8\nmap_id:\t99\n"
	otherMapFdinfo := "pos:\t0\nmap_type:\t2\nmap_id:\t5\n"
	progFdinfo := "pos:\t0\nprog_type:\t26\nprog_id:\t42\n"

	// loader: holds map 99 (twice -> deduped) and a prog fd (ignored).
	writeProcEntry(t, root, "1000", "loader", map[string][2]string{
		"3": {"anon_inode:bpf-map", mapFdinfo},
		"4": {"anon_inode:bpf-map", mapFdinfo},
		"5": {"anon_inode:bpf-prog", progFdinfo},
		"6": {"/dev/null", ""},
	})
	// agent: also holds map 99, plus map 5.
	writeProcEntry(t, root, "1001", "agent", map[string][2]string{
		"3": {"anon_inode:bpf-map", mapFdinfo},
		"7": {"anon_inode:bpf-map", otherMapFdinfo},
	})

	got := scanMapPIDs(root)

	if len(got[99]) != 2 {
		t.Fatalf("map 99: want 2 holders, got %d (%+v)", len(got[99]), got[99])
	}
	pids := map[uint32]string{}
	for _, r := range got[99] {
		pids[r.PID] = r.Comm
	}
	if pids[1000] != "loader" || pids[1001] != "agent" {
		t.Errorf("map 99 holders = %+v, want loader(1000) and agent(1001)", got[99])
	}
	if len(got[5]) != 1 || got[5][0].PID != 1001 {
		t.Errorf("map 5 holders = %+v, want just agent(1001)", got[5])
	}
	if _, ok := got[42]; ok {
		t.Errorf("prog id 42 must not appear among map holders")
	}
}
