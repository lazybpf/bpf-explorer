package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// TestFeaturesPage checks the page reads the way bpftool prints it - its
// sentences for the sysctls, "is set to" / "is not set" for the config - and
// keeps a probe that could not run apart from one the kernel said no to.
func TestFeaturesPage(t *testing.T) {
	out := renderUtil(t, "features", pageData{Node: "node-a", Tab: "features", Features: &pb.ProbeFeaturesResponse{
		Sysctls: []*pb.Sysctl{
			{Name: "unprivileged_bpf_disabled", Value: 2, Readable: true},
			{Name: "bpf_jit_enable", Value: 1, Readable: true},
			{Name: "bpf_jit_harden", Note: "permission denied"},
			{Name: "bpf_jit_limit", Value: 264241152, Readable: true},
		},
		KernelConfigSource: "/proc/1/root/boot/config-6.1.0",
		KernelConfig: []*pb.KernelConfigOption{
			{Name: "CONFIG_BPF", Value: "y"},
			{Name: "CONFIG_BPF_JIT_ALWAYS_ON"},
		},
		BpfSyscall:   true,
		ProgramTypes: []*pb.FeatureProbe{{Name: "xdp", Available: true}, {Name: "netfilter"}},
		MapTypes:     []*pb.FeatureProbe{{Name: "arena", Note: "operation not permitted"}},
		Misc:         []*pb.FeatureProbe{{Name: "Bounded loop support", Available: true}},
	}})

	for _, want := range []string{
		"bpf() syscall restricted to privileged users (admin can change)",
		"JIT compiler is enabled",
		"Unable to retrieve JIT hardening status",
		"permission denied",
		"Global memory limit for JIT compiler for unprivileged users is 264241152 bytes",
		"/proc/1/root/boot/config-6.1.0",
		"is set to <code>y</code>",
		"is not set",
		"bpf() syscall is available",
		"1 of 2 available",
		"NOT available",
		`title="operation not permitted">could not probe`,
		"Bounded loop support",
		"loops the verifier can prove terminate",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the page to contain %q\n%s", want, out)
		}
	}
	if !strings.Contains(out, `class="active" href="/nodes/node-a/features"`) {
		t.Error("expected the tab bar to link the features page and mark it as the one open")
	}
	if strings.Contains(out, `/utils/features`) {
		t.Error("expected no link to the features page's old path under utils")
	}
}

// TestFeaturesPageNoKernelConfig covers the node without a readable config -
// every container whose agent cannot reach pid 1's root.
func TestFeaturesPageNoKernelConfig(t *testing.T) {
	out := renderUtil(t, "features", pageData{Node: "node-a", Tab: "features", Features: &pb.ProbeFeaturesResponse{
		KernelConfigNote: "open /proc/config.gz: no such file or directory",
	}})
	for _, want := range []string{"No kernel config found", "open /proc/config.gz: no such file or directory"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the page to contain %q\n%s", want, out)
		}
	}
}

// TestFeaturesPageMovedOutOfUtils covers the path the page had under utils,
// before it got a tab of its own.
func TestFeaturesPageMovedOutOfUtils(t *testing.T) {
	h, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nodes/node-a/utils/features", nil))

	if rec.Code != http.StatusFound {
		t.Errorf("GET /nodes/node-a/utils/features = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != "/nodes/node-a/features" {
		t.Errorf("redirected to %q, want %q", got, "/nodes/node-a/features")
	}
}
