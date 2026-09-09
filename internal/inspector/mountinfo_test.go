package inspector

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseMountinfo covers the one field that cannot be counted to from either
// end: the filesystem type, which sits after a separator that optional fields
// come before.
func TestParseMountinfo(t *testing.T) {
	tests := []struct {
		name string
		line string
		want mountEntry
		ok   bool
	}{
		{
			"with optional fields",
			"36 26 0:31 / /sys/fs/cgroup rw,nosuid,nodev shared:9 - cgroup2 cgroup2 rw,nsdelegate",
			mountEntry{Device: "0:31", Point: "/sys/fs/cgroup", FSType: "cgroup2"},
			true,
		},
		{
			// The mount a container in its own cgroup namespace gets. Its root
			// field is deliberately not read: from inside that namespace the
			// kernel translates it to "/" like everything else - see cgroupNS.
			"mounted from a subtree",
			"1234 1233 0:31 /kubepods.slice/pod9f.slice/cri-containerd-77.scope /sys/fs/cgroup ro,nosuid - cgroup2 cgroup rw",
			mountEntry{Device: "0:31", Point: "/sys/fs/cgroup", FSType: "cgroup2"},
			true,
		},
		{
			"no optional fields",
			"31 24 0:26 / /sys/fs/cgroup/memory rw,nosuid - cgroup cgroup rw,memory",
			mountEntry{Device: "0:26", Point: "/sys/fs/cgroup/memory", FSType: "cgroup"},
			true,
		},
		{
			// A mount point that is itself a dash sits among the fixed fields,
			// where the separator is not looked for.
			"dash as a mount point",
			"22 21 0:19 / /- rw shared:4 - tmpfs tmpfs rw",
			mountEntry{Device: "0:19", Point: "/-", FSType: "tmpfs"},
			true,
		},
		{"too short to mean anything", "36 26 0:31 /", mountEntry{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseMountinfo(tc.line)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Errorf("parseMountinfo =\n%+v\nwant\n%+v", got, tc.want)
			}
		})
	}
}

// TestReadMounts checks the device index the inode lookup names its matches
// from, and that pid 1's table - the node's, with hostPID - is preferred to the
// agent's own.
func TestReadMounts(t *testing.T) {
	root := t.TempDir()
	writeMountinfo(t, root, "1", ""+
		"26 32 0:24 / /sys rw,relatime shared:7 - sysfs sysfs rw\n"+
		"32 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n"+
		// A bind mount of a filesystem already named: the first mount point wins.
		"40 32 259:2 /var/lib /mnt/data rw,relatime shared:3 - ext4 /dev/nvme0n1p2 rw\n")
	writeMountinfo(t, root, "self", "99 32 0:99 / /container rw - overlay overlay rw\n")

	mounts := readMounts(root)
	if got := mounts["259:2"]; got != "/" {
		t.Errorf("mount for 259:2 = %q, want / - the first one named", got)
	}
	if got := mounts["0:24"]; got != "/sys" {
		t.Errorf("mount for 0:24 = %q, want /sys", got)
	}
	if _, ok := mounts["0:99"]; ok {
		t.Errorf("read the agent's own table while pid 1's was there:\n%+v", mounts)
	}

	// With pid 1 unreadable the agent's own table is what there is.
	own := t.TempDir()
	writeMountinfo(t, own, "self", "99 32 0:99 / /container rw - overlay overlay rw\n")
	if got := readMounts(own)["0:99"]; got != "/container" {
		t.Errorf("mount for 0:99 = %q, want /container from the agent's own table", got)
	}
}

// writeMountinfo lays out a fake /proc/<pid>/mountinfo.
func writeMountinfo(t *testing.T, root, pid, contents string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mountinfo"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
