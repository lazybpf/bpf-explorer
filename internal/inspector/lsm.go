package inspector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ActiveLSMs returns the LSMs the kernel calls, in its order, as
// /sys/kernel/security/lsm lists them - "lockdown,capability,...,bpf". A BPF
// LSM program only runs when "bpf" is among them: without it the kernel still
// loads and attaches one, but never calls the hook it sits on.
func (i *Inspector) ActiveLSMs() ([]string, error) {
	return readActiveLSMs("/proc", "/")
}

// readActiveLSMs reads the list from the agent's own securityfs first, then
// through pid 1's root. The list is the kernel's and the same from anywhere,
// but securityfs is a mount of its own that a container is not given: in the
// DaemonSet /sys/kernel/security is an empty directory, and only the node's
// mount table (reached with hostPID) has the file. The local read comes first
// because /proc/1/root takes root, and an unprivileged run has securityfs.
func readActiveLSMs(procRoot, root string) ([]string, error) {
	const file = "sys/kernel/security/lsm"
	b, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		var err1 error
		if b, err1 = os.ReadFile(filepath.Join(procRoot, "1", "root", file)); err1 != nil {
			return nil, errors.Join(err, err1)
		}
	}
	var out []string
	for _, name := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}
