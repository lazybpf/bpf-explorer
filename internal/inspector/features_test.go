package inspector

import (
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

// TestReadKernelConfig covers where the options come from: pid 1's /boot ahead
// of the agent's own, /proc/config.gz when there is no file for the release,
// and an option the file does not set - commented out or not there - as unset.
func TestReadKernelConfig(t *testing.T) {
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
	nodeConfig := filepath.Join(procRoot, "1", "root", "boot", "config-6.1.0")
	write(nodeConfig, "CONFIG_BPF=y\n# CONFIG_BPF_JIT_ALWAYS_ON is not set\nCONFIG_NET_CLS_BPF=m\nCONFIG_HZ=250\n")
	write(filepath.Join(root, "boot", "config-6.1.0"), "CONFIG_BPF=n\n")

	opts, source, note := readKernelConfig(procRoot, root, "6.1.0")
	if source != nodeConfig || note != "" {
		t.Fatalf("source %q note %q: want the node's own /boot", source, note)
	}
	got := map[string]string{}
	for _, o := range opts {
		got[o.Name] = o.Value
	}
	if len(opts) != len(kernelConfigOptions) {
		t.Errorf("got %d options, want every one bpftool prints (%d)", len(opts), len(kernelConfigOptions))
	}
	for name, want := range map[string]string{
		"CONFIG_BPF": "y", "CONFIG_NET_CLS_BPF": "m", "CONFIG_HZ": "250",
		"CONFIG_BPF_JIT_ALWAYS_ON": "", "CONFIG_BPF_SYSCALL": "",
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
	}

	// No file for this release anywhere: the kernel's own gzipped copy.
	gzPath := filepath.Join(procRoot, "config.gz")
	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	fmt.Fprint(gz, "CONFIG_BPF_SYSCALL=y\n")
	gz.Close()
	f.Close()
	opts, source, _ = readKernelConfig(procRoot, root, "6.2.0")
	if source != gzPath || opts[1].Name != "CONFIG_BPF_SYSCALL" || opts[1].Value != "y" {
		t.Errorf("source %q, %+v: want CONFIG_BPF_SYSCALL=y from %s", source, opts[1], gzPath)
	}

	// Nothing at all: no options, and a note naming what was tried.
	os.Remove(gzPath)
	opts, source, note = readKernelConfig(procRoot, root, "6.2.0")
	if opts != nil || source != "" || note == "" {
		t.Errorf("opts %v source %q note %q: want nothing, with a note", opts, source, note)
	}
}

// TestReadSysctls checks a knob that cannot be read is reported as such, with
// why, rather than as a zero - 0 is a real setting for every one of them.
func TestReadSysctls(t *testing.T) {
	procRoot := t.TempDir()
	dir := filepath.Join(procRoot, "sys", "kernel")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "unprivileged_bpf_disabled"), []byte("2\n"), 0o644)
	jit := filepath.Join(procRoot, "sys", "net", "core")
	os.MkdirAll(jit, 0o755)
	os.WriteFile(filepath.Join(jit, "bpf_jit_limit"), []byte("264241152\n"), 0o644)

	got, note := readSysctls(procRoot)
	if note != "" {
		t.Errorf("note %q: a fake /proc has no namespaces to cross", note)
	}
	if len(got) != len(sysctlFiles) {
		t.Fatalf("got %d sysctls, want %d", len(got), len(sysctlFiles))
	}
	if s := got[0]; s.Name != "unprivileged_bpf_disabled" || !s.Readable || s.Value != 2 {
		t.Errorf("%+v: want unprivileged_bpf_disabled = 2", s)
	}
	if s := got[1]; s.Name != "bpf_jit_enable" || s.Readable || s.Note == "" {
		t.Errorf("%+v: want bpf_jit_enable unreadable, with a note", s)
	}
	if s := got[4]; s.Name != "bpf_jit_limit" || !s.Readable || s.Value != 264241152 {
		t.Errorf("%+v: want bpf_jit_limit = 264241152", s)
	}
}

// TestProbeResult pins the three outcomes apart: an EPERM must not read as the
// kernel lacking the feature, which is how bpftool would print it.
func TestProbeResult(t *testing.T) {
	if p := probeResult("xdp", nil); !p.Available || p.Note != "" {
		t.Errorf("nil: %+v, want available", p)
	}
	if p := probeResult("xdp", fmt.Errorf("xdp: %w", ebpf.ErrNotSupported)); p.Available || p.Note != "" {
		t.Errorf("ErrNotSupported: %+v, want not available and no note", p)
	}
	if p := probeResult("xdp", errors.New("operation not permitted")); p.Available || p.Note == "" {
		t.Errorf("EPERM: %+v, want not available with a note", p)
	}
}
