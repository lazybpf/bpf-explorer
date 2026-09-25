package web

import (
	"context"
	"fmt"
	"net/http"
	"time"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
)

// features shows what the node's kernel supports for BPF - `bpftool feature
// probe`, section by section. It is the question asked before anything is
// loaded, where the node page answers what the node is and the object tabs
// what is loaded on it.
func (h *Handlers) features(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	data := pageData{Node: node, Tab: "utils", Util: "features"}
	data.Nodes, _ = h.nodes()

	conn, err := h.dial(node)
	if err != nil {
		data.Err = err.Error()
		h.render(w, "features", data)
		return
	}
	defer conn.Close()
	client := pb.NewBpfInspectorClient(conn)

	// Some seventy loads and map creations the first time, cached after that.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	f, err := client.ProbeFeatures(ctx, &pb.ProbeFeaturesRequest{})
	if err != nil {
		data.Err = err.Error()
		h.render(w, "features", data)
		return
	}
	data.Features = f
	h.render(w, "features", data)
}

// sysctlText says what a system-configuration knob is set to in bpftool's own
// words, so a line on the page can be matched against `bpftool feature probe`
// by eye. The strings are the ones in the bpftool v7.5 binary.
func sysctlText(s *pb.Sysctl) string {
	v := s.Value
	switch s.Name {
	case "unprivileged_bpf_disabled":
		if !s.Readable {
			return "Unable to retrieve required privileges for bpf() syscall"
		}
		switch v {
		case 0:
			return "bpf() syscall for unprivileged users is enabled"
		case 1:
			return "bpf() syscall restricted to privileged users (without recovery)"
		case 2:
			return "bpf() syscall restricted to privileged users (admin can change)"
		}
		return fmt.Sprintf("bpf() syscall restriction has unknown value %d", v)
	case "bpf_jit_enable":
		if !s.Readable {
			return "Unable to retrieve JIT-compiler status"
		}
		switch v {
		case 0:
			return "JIT compiler is disabled"
		case 1:
			return "JIT compiler is enabled"
		case 2:
			return "JIT compiler is enabled with debugging traces in kernel logs"
		}
		return fmt.Sprintf("JIT-compiler status has unknown value %d", v)
	case "bpf_jit_harden":
		if !s.Readable {
			return "Unable to retrieve JIT hardening status"
		}
		switch v {
		case 0:
			return "JIT compiler hardening is disabled"
		case 1:
			return "JIT compiler hardening is enabled for unprivileged users"
		case 2:
			return "JIT compiler hardening is enabled for all users"
		}
		return fmt.Sprintf("JIT hardening status has unknown value %d", v)
	case "bpf_jit_kallsyms":
		if !s.Readable {
			return "Unable to retrieve JIT kallsyms export status"
		}
		switch v {
		case 0:
			return "JIT compiler kallsyms exports are disabled"
		case 1:
			return "JIT compiler kallsyms exports are enabled for root"
		}
		return fmt.Sprintf("JIT kallsyms exports status has unknown value %d", v)
	case "bpf_jit_limit":
		if !s.Readable {
			return "Unable to retrieve global memory limit for JIT compiler for unprivileged users"
		}
		return fmt.Sprintf("Global memory limit for JIT compiler for unprivileged users is %d bytes", v)
	}
	if !s.Readable {
		return "unreadable"
	}
	return fmt.Sprint(v)
}

// featureHelps says what a verifier feature lets a program do, for the probes
// whose name alone does not.
var featureHelps = map[string]string{
	"Large program size limit": "programs of up to a million instructions rather than 4096, for privileged loaders (5.2)",
	"Bounded loop support":     "loops the verifier can prove terminate, without unrolling them (5.3)",
	"ISA extension v2":         "the jump-if-less-than family: JLT, JLE, JSLT, JSLE (4.14)",
	"ISA extension v3":         "32-bit conditional jumps (JMP32), which compilers use for 32-bit comparisons (5.1)",
	"ISA extension v4":         "sign-extending loads and moves, signed division and modulo, unconditional byte swap, and a jump with a 32-bit offset (6.6)",
}

func featureHelp(name string) string { return featureHelps[name] }

// availableCount is the "n of m" over a section's probes, for its heading.
func availableCount(probes []*pb.FeatureProbe) string {
	n := 0
	for _, p := range probes {
		if p.Available {
			n++
		}
	}
	return fmt.Sprintf("%d of %d", n, len(probes))
}
