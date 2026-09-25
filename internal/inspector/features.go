package inspector

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// Features is what `bpftool feature probe` reports, section by section and in
// its order: the system configuration, whether there is a bpf() syscall at all,
// and which program types, map types and verifier features this kernel has.
// The per-program-type helper lists are not probed yet.
type Features struct {
	Sysctls []Sysctl
	// SysctlNote says why the bpf_jit_* values are the agent's own namespace's
	// rather than the node's, when they are.
	SysctlNote   string
	KernelConfig []ConfigOption
	// KernelConfigSource is the file the options were read from; empty when no
	// config file could be read, and KernelConfigNote then says why.
	KernelConfigSource string
	KernelConfigNote   string
	BPFSyscall         bool
	ProgramTypes       []Probe
	MapTypes           []Probe
	Misc               []Probe
}

// Sysctl is one of the knobs bpftool reads under "system configuration". Value
// is only meaningful when Readable; Note is why it is not.
type Sysctl struct {
	Name     string // bpftool's key, e.g. "bpf_jit_enable"
	Value    int64
	Readable bool
	Note     string
}

// ConfigOption is one kernel build option. Value is what the config file sets
// it to - "y", "m", a number, a quoted string - and empty when it is not set.
type ConfigOption struct {
	Name  string
	Value string
}

// Probe is the outcome of one feature probe. A probe that could not be run -
// no permission to load a program, say - is neither available nor unavailable,
// and Note says what went wrong instead.
type Probe struct {
	Name      string // bpftool's spelling, e.g. "sched_cls", "lru_percpu_hash"
	Available bool
	Note      string
}

// sysctlFiles are bpftool's system-configuration knobs, in its order, and where
// each one lives under /proc/sys. The bpf_jit_* ones are net.core sysctls the
// kernel registers in the initial network namespace only: in a pod's own netns
// the files are not there at all.
var sysctlFiles = []struct {
	name, path string
	netns      bool
}{
	{"unprivileged_bpf_disabled", "sys/kernel/unprivileged_bpf_disabled", false},
	{"bpf_jit_enable", "sys/net/core/bpf_jit_enable", true},
	{"bpf_jit_harden", "sys/net/core/bpf_jit_harden", true},
	{"bpf_jit_kallsyms", "sys/net/core/bpf_jit_kallsyms", true},
	{"bpf_jit_limit", "sys/net/core/bpf_jit_limit", true},
}

// kernelConfigOptions are the options bpftool v7.5 prints, in its order.
var kernelConfigOptions = []string{
	"CONFIG_BPF",
	"CONFIG_BPF_SYSCALL",
	"CONFIG_HAVE_EBPF_JIT",
	"CONFIG_BPF_JIT",
	"CONFIG_BPF_JIT_ALWAYS_ON",
	"CONFIG_DEBUG_INFO_BTF",
	"CONFIG_DEBUG_INFO_BTF_MODULES",
	"CONFIG_CGROUPS",
	"CONFIG_CGROUP_BPF",
	"CONFIG_CGROUP_NET_CLASSID",
	"CONFIG_SOCK_CGROUP_DATA",
	"CONFIG_BPF_EVENTS",
	"CONFIG_KPROBE_EVENTS",
	"CONFIG_UPROBE_EVENTS",
	"CONFIG_TRACING",
	"CONFIG_FTRACE_SYSCALLS",
	"CONFIG_FUNCTION_ERROR_INJECTION",
	"CONFIG_BPF_KPROBE_OVERRIDE",
	"CONFIG_NET",
	"CONFIG_XDP_SOCKETS",
	"CONFIG_LWTUNNEL_BPF",
	"CONFIG_NET_ACT_BPF",
	"CONFIG_NET_CLS_BPF",
	"CONFIG_NET_CLS_ACT",
	"CONFIG_NET_SCH_INGRESS",
	"CONFIG_XFRM",
	"CONFIG_IP_ROUTE_CLASSID",
	"CONFIG_IPV6_SEG6_BPF",
	"CONFIG_BPF_LIRC_MODE2",
	"CONFIG_BPF_STREAM_PARSER",
	"CONFIG_NETFILTER_XT_MATCH_BPF",
	"CONFIG_TEST_BPF",
	"CONFIG_HZ",
}

// programTypes and mapTypes are the kernel's enums in their order, spelled the
// way libbpf and bpftool spell them rather than the way cilium/ebpf does.
var programTypes = []struct {
	name string
	t    ebpf.ProgramType
}{
	{"socket_filter", ebpf.SocketFilter},
	{"kprobe", ebpf.Kprobe},
	{"sched_cls", ebpf.SchedCLS},
	{"sched_act", ebpf.SchedACT},
	{"tracepoint", ebpf.TracePoint},
	{"xdp", ebpf.XDP},
	{"perf_event", ebpf.PerfEvent},
	{"cgroup_skb", ebpf.CGroupSKB},
	{"cgroup_sock", ebpf.CGroupSock},
	{"lwt_in", ebpf.LWTIn},
	{"lwt_out", ebpf.LWTOut},
	{"lwt_xmit", ebpf.LWTXmit},
	{"sock_ops", ebpf.SockOps},
	{"sk_skb", ebpf.SkSKB},
	{"cgroup_device", ebpf.CGroupDevice},
	{"sk_msg", ebpf.SkMsg},
	{"raw_tracepoint", ebpf.RawTracepoint},
	{"cgroup_sock_addr", ebpf.CGroupSockAddr},
	{"lwt_seg6local", ebpf.LWTSeg6Local},
	{"lirc_mode2", ebpf.LircMode2},
	{"sk_reuseport", ebpf.SkReuseport},
	{"flow_dissector", ebpf.FlowDissector},
	{"cgroup_sysctl", ebpf.CGroupSysctl},
	{"raw_tracepoint_writable", ebpf.RawTracepointWritable},
	{"cgroup_sockopt", ebpf.CGroupSockopt},
	{"tracing", ebpf.Tracing},
	{"struct_ops", ebpf.StructOps},
	{"ext", ebpf.Extension},
	{"lsm", ebpf.LSM},
	{"sk_lookup", ebpf.SkLookup},
	{"syscall", ebpf.Syscall},
	{"netfilter", ebpf.Netfilter},
}

var mapTypes = []struct {
	name string
	t    ebpf.MapType
}{
	{"hash", ebpf.Hash},
	{"array", ebpf.Array},
	{"prog_array", ebpf.ProgramArray},
	{"perf_event_array", ebpf.PerfEventArray},
	{"percpu_hash", ebpf.PerCPUHash},
	{"percpu_array", ebpf.PerCPUArray},
	{"stack_trace", ebpf.StackTrace},
	{"cgroup_array", ebpf.CGroupArray},
	{"lru_hash", ebpf.LRUHash},
	{"lru_percpu_hash", ebpf.LRUCPUHash},
	{"lpm_trie", ebpf.LPMTrie},
	{"array_of_maps", ebpf.ArrayOfMaps},
	{"hash_of_maps", ebpf.HashOfMaps},
	{"devmap", ebpf.DevMap},
	{"sockmap", ebpf.SockMap},
	{"cpumap", ebpf.CPUMap},
	{"xskmap", ebpf.XSKMap},
	{"sockhash", ebpf.SockHash},
	{"cgroup_storage", ebpf.CGroupStorage},
	{"reuseport_sockarray", ebpf.ReusePortSockArray},
	{"percpu_cgroup_storage", ebpf.PerCPUCGroupStorage},
	{"queue", ebpf.Queue},
	{"stack", ebpf.Stack},
	{"sk_storage", ebpf.SkStorage},
	{"devmap_hash", ebpf.DevMapHash},
	{"struct_ops", ebpf.StructOpsMap},
	{"ringbuf", ebpf.RingBuf},
	{"inode_storage", ebpf.InodeStorage},
	{"task_storage", ebpf.TaskStorage},
	{"bloom_filter", ebpf.BloomFilter},
	{"user_ringbuf", ebpf.UserRingbuf},
	{"cgrp_storage", ebpf.CgroupStorage},
	{"arena", ebpf.Arena},
}

// miscProbes are bpftool's "miscellaneous eBPF features", in its words, plus
// ISA v4, which cilium/ebpf probes and bpftool v7.5 does not print.
var miscProbes = []struct {
	name  string
	probe func() error
}{
	{"Large program size limit", features.HaveLargeInstructions},
	{"Bounded loop support", features.HaveBoundedLoops},
	{"ISA extension v2", features.HaveV2ISA},
	{"ISA extension v3", features.HaveV3ISA},
	{"ISA extension v4", features.HaveV4ISA},
}

// ProbeFeatures reports what this kernel supports for BPF. The type probes load
// a trivial program or create a one-entry map and close it straight away -
// what bpftool does - and cilium/ebpf caches each answer for the life of the
// agent, since a kernel does not gain features without a reboot.
func (i *Inspector) ProbeFeatures() Features {
	f := Features{BPFSyscall: haveBPFSyscall()}
	f.Sysctls, f.SysctlNote = readSysctls("/proc")
	var release string
	var u unix.Utsname
	if err := unix.Uname(&u); err == nil {
		release = utsString(u.Release[:])
	}
	f.KernelConfig, f.KernelConfigSource, f.KernelConfigNote = readKernelConfig("/proc", "/", release)
	for _, p := range programTypes {
		f.ProgramTypes = append(f.ProgramTypes, probeResult(p.name, features.HaveProgramType(p.t)))
	}
	for _, m := range mapTypes {
		f.MapTypes = append(f.MapTypes, probeResult(m.name, features.HaveMapType(m.t)))
	}
	for _, m := range miscProbes {
		f.Misc = append(f.Misc, probeResult(m.name, m.probe()))
	}
	return f
}

// probeResult reads a cilium/ebpf probe's error the way its package documents
// it: nil is available, ErrNotSupported is not, and anything else means the
// probe did not get an answer. bpftool reports that last case as "NOT
// available" too; it is kept apart here because an EPERM from an agent without
// CAP_BPF says nothing about the kernel.
func probeResult(name string, err error) Probe {
	switch {
	case err == nil:
		return Probe{Name: name, Available: true}
	case errors.Is(err, ebpf.ErrNotSupported):
		return Probe{Name: name}
	default:
		return Probe{Name: name, Note: err.Error()}
	}
}

// haveBPFSyscall is bpftool's check: a BPF_PROG_LOAD with no attributes fails
// either way, and only ENOSYS says there is no syscall to fail in.
func haveBPFSyscall() bool {
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, 0, 0)
	return errno != unix.ENOSYS
}

// readSysctls reads bpftool's system-configuration knobs. The bpf_jit_* files
// exist only in the node's initial network namespace, and the agent's pod has a
// namespace of its own unless it runs with hostNetwork - so they are read on a
// thread that has joined pid 1's, as the cgroup paths are read in its cgroup
// namespace.
func readSysctls(procRoot string) ([]Sysctl, string) {
	out := make([]Sysctl, 0, len(sysctlFiles))
	var jit []int
	for idx, s := range sysctlFiles {
		out = append(out, Sysctl{Name: s.name})
		if s.netns {
			jit = append(jit, idx)
			continue
		}
		out[idx] = readSysctl(procRoot, s.name, s.path)
	}
	readJIT := func() {
		for _, idx := range jit {
			out[idx] = readSysctl(procRoot, sysctlFiles[idx].name, sysctlFiles[idx].path)
		}
	}

	self, okSelf := nsInode(filepath.Join(procRoot, "self"), "net")
	init, okInit := nsInode(filepath.Join(procRoot, "1"), "net")
	if !okSelf || !okInit || self == init {
		readJIT()
		return out, ""
	}
	if err := runInNS(filepath.Join(procRoot, "1", "ns", "net"), unix.CLONE_NEWNET, readJIT); err != nil {
		readJIT()
		return out, "The JIT settings could not be read from the node: " + err.Error()
	}
	return out, ""
}

func readSysctl(procRoot, name, path string) Sysctl {
	s := Sysctl{Name: name}
	b, err := os.ReadFile(filepath.Join(procRoot, path))
	if err != nil {
		s.Note = err.Error()
		return s
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		s.Note = err.Error()
		return s
	}
	s.Value, s.Readable = v, true
	return s
}

// readKernelConfig reads the kernel's build options from where bpftool looks:
// /boot/config-<release>, then /proc/config.gz. /boot is tried through pid 1's
// root first, since the agent's own /boot is its container image's and holds
// nothing; /proc/config.gz is the kernel's own and the same from anywhere.
func readKernelConfig(procRoot, root, release string) ([]ConfigOption, string, string) {
	var candidates []string
	if release != "" {
		candidates = append(candidates,
			filepath.Join(procRoot, "1", "root", "boot", "config-"+release),
			filepath.Join(root, "boot", "config-"+release))
	}
	candidates = append(candidates, filepath.Join(procRoot, "config.gz"))

	var errs []string
	for _, path := range candidates {
		values, err := readConfigFile(path)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		opts := make([]ConfigOption, 0, len(kernelConfigOptions))
		for _, name := range kernelConfigOptions {
			opts = append(opts, ConfigOption{Name: name, Value: values[name]})
		}
		return opts, path, ""
	}
	return nil, "", strings.Join(errs, "; ")
}

// readConfigFile parses a kernel config, gzipped when its name says so. Only
// "NAME=value" lines set anything: "# NAME is not set" is the same as absent.
func readConfigFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	values := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		name, value, ok := strings.Cut(sc.Text(), "=")
		if ok && strings.HasPrefix(name, "CONFIG_") {
			values[name] = value
		}
	}
	return values, sc.Err()
}
