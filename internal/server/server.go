// Package server adapts an *inspector.Inspector to the generated gRPC
// BpfInspectorServer interface. It holds no kernel logic — just translation
// between proto messages and inspector calls.
package server

import (
	"context"
	"strings"
	"time"

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
	"github.com/lazybpf/bpf-explorer/internal/inspector"
	"github.com/lazybpf/bpf-explorer/internal/tracelog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Server implements pb.BpfInspectorServer.
type Server struct {
	pb.UnimplementedBpfInspectorServer
	insp         *inspector.Inspector
	hub          *tracelog.Hub
	stats        *inspector.StatsSwitch
	tetragonAddr string
}

func New(insp *inspector.Inspector, hub *tracelog.Hub, stats *inspector.StatsSwitch, tetragonAddr ...string) *Server {
	addr := "unix:///var/run/tetragon/tetragon.sock"
	if len(tetragonAddr) > 0 && tetragonAddr[0] != "" {
		addr = tetragonAddr[0]
	}
	return &Server{insp: insp, hub: hub, stats: stats, tetragonAddr: addr}
}

// ListTetragonPolicies asks the local Tetragon daemon for its current policy
// state. It is read-only and deliberately uses Tetragon's gRPC API directly.
func (s *Server) ListTetragonPolicies(ctx context.Context, req *pb.ListTetragonPoliciesRequest) (*pb.ListTetragonPoliciesResponse, error) {
	addr := req.GetAddress()
	if addr == "" {
		addr = s.tetragonAddr
	}
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	res, err := tetragon.NewFineGuidanceSensorsClient(conn).ListTracingPolicies(ctx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil {
		return nil, err
	}
	out := &pb.ListTetragonPoliciesResponse{Policies: make([]*pb.TetragonPolicyInfo, 0, len(res.GetPolicies()))}
	for _, p := range res.GetPolicies() {
		counters := p.GetStats().GetActionCounters()
		var post, enforce, monitor uint64
		if counters != nil {
			post = counters.GetPost()
			enforce = counters.GetSignal() + counters.GetOverride() + counters.GetNotifyEnforcer() + counters.GetSet()
			monitor = counters.GetMonitorSignal() + counters.GetMonitorOverride() + counters.GetMonitorNotifyEnforcer() + counters.GetMonitorSet()
		}
		out.Policies = append(out.Policies, &pb.TetragonPolicyInfo{
			Id: p.GetId(), Name: p.GetName(), Namespace: p.GetNamespace(),
			State: strings.ToLower(strings.TrimPrefix(p.GetState().String(), "TP_STATE_")),
			Mode:  strings.ToLower(strings.TrimPrefix(p.GetMode().String(), "TP_MODE_")),
			Error: p.GetError(), Sensors: p.GetSensors(), FilterId: p.GetFilterId(),
			KernelMemoryBytes: p.GetKernelMemoryBytes(), Npost: post, Nenforce: enforce, Nmonitor: monitor,
		})
	}
	return out, nil
}

func (s *Server) ListMaps(_ context.Context, _ *pb.ListMapsRequest) (*pb.ListMapsResponse, error) {
	maps, err := s.insp.ListMaps()
	if err != nil {
		return nil, err
	}
	resp := &pb.ListMapsResponse{Maps: make([]*pb.MapInfo, 0, len(maps))}
	for _, m := range maps {
		pids := make([]*pb.ProcessRef, 0, len(m.PIDs))
		for _, ref := range m.PIDs {
			pids = append(pids, &pb.ProcessRef{Pid: ref.PID, Comm: ref.Comm})
		}
		resp.Maps = append(resp.Maps, &pb.MapInfo{
			Id:          m.ID,
			Name:        m.Name,
			Type:        m.Type,
			KeySize:     m.KeySize,
			ValueSize:   m.ValueSize,
			MaxEntries:  m.MaxEntries,
			Flags:       m.Flags,
			Dumpable:    m.Dumpable,
			DumpNote:    m.DumpNote,
			Pids:        pids,
			InnerMapIds: m.InnerMapIDs,
			ProgIds:     m.ProgIDs,
			Frozen:      m.Frozen,
		})
	}
	return resp, nil
}

func (s *Server) DumpMap(_ context.Context, req *pb.DumpMapRequest) (*pb.DumpMapResponse, error) {
	dump, err := s.insp.DumpMap(req.GetId(), req.GetLimit())
	if err != nil {
		return nil, err
	}
	resp := &pb.DumpMapResponse{
		Entries:   make([]*pb.MapEntry, 0, len(dump.Entries)),
		Truncated: dump.Truncated,
	}
	for _, e := range dump.Entries {
		resp.Entries = append(resp.Entries, &pb.MapEntry{
			KeyHex:     e.KeyHex,
			KeyFmt:     e.KeyFmt,
			ValueHex:   e.ValueHex,
			ValueFmt:   e.ValueFmt,
			InnerMapId: e.InnerMapID,
			ProgId:     e.ProgID,
		})
	}
	return resp, nil
}

// cpuSample is how long ListPrograms samples run time for when asked to.
const cpuSample = time.Second

func (s *Server) ListPrograms(_ context.Context, req *pb.ListProgramsRequest) (*pb.ListProgramsResponse, error) {
	// Read before the listing: whether to sample depends on it, and with stats
	// off no run time moves, so there is nothing to wait a second for.
	st := s.stats.State()
	var sample time.Duration
	if req.GetSampleCpu() && st.On() {
		sample = cpuSample
	}
	progs, err := s.insp.ListPrograms(sample)
	if err != nil {
		return nil, err
	}
	resp := &pb.ListProgramsResponse{Programs: make([]*pb.ProgramInfo, 0, len(progs))}
	for _, p := range progs {
		pids := make([]*pb.ProcessRef, 0, len(p.PIDs))
		for _, ref := range p.PIDs {
			pids = append(pids, &pb.ProcessRef{Pid: ref.PID, Comm: ref.Comm})
		}
		// A zero LoadedAt is "the node could not date this one", which UnixNano
		// would send as a date in 1754 rather than as nothing.
		var loadedAt int64
		if !p.LoadedAt.IsZero() {
			loadedAt = p.LoadedAt.UnixNano()
		}
		var cpu *float64
		if p.HasCPU {
			cpu = &p.CPUPercent
		}
		resp.Programs = append(resp.Programs, &pb.ProgramInfo{
			Id:               p.ID,
			Name:             p.Name,
			Type:             p.Type,
			Tag:              p.Tag,
			MapIds:           p.MapIDs,
			Pids:             pids,
			LoadedAtUnixNano: loadedAt,
			RunCount:         p.RunCount,
			RunTimeNs:        uint64(p.RunTime),
			RecursionMisses:  p.RecursionMisses,
			CpuPercent:       cpu,
		})
	}
	resp.Stats = statsState(st)
	return resp, nil
}

// SetStats turns the agent's stats switch on or off. A kernel refusal (before
// 5.8, or without CAP_SYS_ADMIN) comes back as the kernel's error.
func (s *Server) SetStats(_ context.Context, req *pb.SetStatsRequest) (*pb.StatsState, error) {
	st, err := s.stats.Set(req.GetEnabled())
	if err != nil {
		return nil, err
	}
	return statsState(st), nil
}

func statsState(st inspector.StatsState) *pb.StatsState {
	holders := make([]*pb.ProcessRef, 0, len(st.Holders))
	for _, ref := range st.Holders {
		holders = append(holders, &pb.ProcessRef{Pid: ref.PID, Comm: ref.Comm})
	}
	return &pb.StatsState{
		Held: st.Held,
		// Rounded up, so the last second of a hold does not read as none.
		SecondsLeft: uint32((st.Left + time.Second - 1) / time.Second),
		Sysctl:      st.Sysctl,
		Holders:     holders,
	}
}

func (s *Server) DumpProgram(_ context.Context, req *pb.DumpProgramRequest) (*pb.DumpProgramResponse, error) {
	dump, err := s.insp.DumpProgram(req.GetId())
	if err != nil {
		return nil, err
	}
	calls := make([]*pb.TailCall, 0, len(dump.TailCalls))
	for _, c := range dump.TailCalls {
		calls = append(calls, &pb.TailCall{
			Site:     c.Site,
			MapId:    c.MapID,
			Index:    c.Index,
			HasIndex: c.HasIndex,
			ProgId:   c.ProgID,
		})
	}
	return &pb.DumpProgramResponse{
		Lines:     dump.Lines,
		Available: dump.Available,
		Note:      dump.Note,
		TailCalls: calls,
	}, nil
}

// TraceLog streams the node's tracefs trace_pipe, like `bpftool prog tracelog`,
// until the client goes away. All concurrent clients share one reader (see
// internal/tracelog): reading the pipe drains the node's global trace buffer.
func (s *Server) TraceLog(_ *pb.TraceLogRequest, stream pb.BpfInspector_TraceLogServer) error {
	sub, err := s.hub.Subscribe()
	if err != nil {
		// tracefs not mounted, not visible to the agent, or not permitted:
		// Unavailable so the UI can show why instead of a bare failure.
		return status.Error(codes.Unavailable, err.Error())
	}
	defer sub.Close()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev, ok := <-sub.Events():
			if !ok {
				return status.Error(codes.Unavailable, "trace_pipe reader stopped")
			}
			if err := stream.Send(&pb.TraceLogEvent{Line: ev.Line, Dropped: ev.Dropped}); err != nil {
				return err
			}
		}
	}
}

// ResolveInode searches the node's open fds and mapped files for an inode. It
// reports no error for a miss: "nothing holds it" is an answer, and the scanned
// count tells the caller how much of /proc that answer rests on.
func (s *Server) ResolveInode(_ context.Context, req *pb.ResolveInodeRequest) (*pb.ResolveInodeResponse, error) {
	res := s.insp.ResolveInode(inspector.InodeQuery{
		Inode:      req.GetInode(),
		Device:     req.GetDevice(),
		Walk:       req.GetWalk(),
		WalkRoot:   req.GetWalkRoot(),
		WalkBudget: time.Duration(req.GetWalkSeconds()) * time.Second,
	})
	matches := res.Matches
	resp := &pb.ResolveInodeResponse{
		Matches:          make([]*pb.InodeMatch, 0, len(matches)),
		ProcessesScanned: res.Scanned,
		Walk: &pb.WalkStats{
			Ran:      res.Walk.Ran,
			Root:     res.Walk.Root,
			Device:   res.Walk.Device,
			Dirs:     res.Walk.Dirs,
			Files:    res.Walk.Files,
			TimedOut: res.Walk.TimedOut,
			Seconds:  res.Walk.Seconds,
			Note:     res.Walk.Note,
		},
	}
	for _, m := range matches {
		holders := make([]*pb.InodeHolder, 0, len(m.Holders))
		for _, h := range m.Holders {
			holders = append(holders, &pb.InodeHolder{
				Pid: h.PID, Comm: h.Comm, Source: h.Source, Fd: h.FD,
			})
		}
		resp.Matches = append(resp.Matches, &pb.InodeMatch{
			Path:     m.Path,
			Device:   m.Device,
			Mount:    m.Mount,
			Deleted:  m.Deleted,
			HostPath: m.HostPath,
			Holders:  holders,
			FromWalk: m.FromWalk,
		})
	}
	return resp, nil
}

// DescribeProcess reports what /proc knows about one pid. A pid that is gone is
// found=false rather than an error: asking about a dead process is the normal
// case when the number came out of a BPF map.
func (s *Server) DescribeProcess(_ context.Context, req *pb.DescribeProcessRequest) (*pb.DescribeProcessResponse, error) {
	d := s.insp.DescribeProcess(req.GetPid())
	namespaces := make([]*pb.Namespace, 0, len(d.Namespaces))
	for _, ns := range d.Namespaces {
		namespaces = append(namespaces, &pb.Namespace{
			Kind: ns.Kind, Inode: ns.Inode, Pid1Inode: ns.PID1Inode,
		})
	}
	return &pb.DescribeProcessResponse{
		Found:      d.Found,
		Pid:        d.PID,
		Comm:       d.Comm,
		State:      d.State,
		Ppid:       d.PPID,
		Uid:        d.UID,
		Cmdline:    d.Cmdline,
		Exe:        d.Exe,
		Cgroup:     d.Cgroup,
		Namespaces: namespaces,
		NsPids:     d.NSPids,
		Resources:  processResources(d.Resources),
	}, nil
}

// GetProcessResources reports what the kernel has accounted to each pid and its
// cgroup. Pids that are gone are left out, not failed on: a loader can exit
// between the list being drawn and this call.
func (s *Server) GetProcessResources(_ context.Context, req *pb.GetProcessResourcesRequest) (*pb.GetProcessResourcesResponse, error) {
	resp := &pb.GetProcessResourcesResponse{Resources: map[uint32]*pb.ProcessResources{}}
	for pid, r := range s.insp.ProcessResources(req.GetPids()) {
		resp.Resources[pid] = processResources(r)
	}
	return resp, nil
}

func processResources(r inspector.ProcessResources) *pb.ProcessResources {
	usec := func(d time.Duration) uint64 { return uint64(d.Microseconds()) }
	c := r.Cgroup
	return &pb.ProcessResources{
		UserCpuUsec:   usec(r.UserCPU),
		SystemCpuUsec: usec(r.SystemCPU),
		RssBytes:      r.RSS,
		PeakRssBytes:  r.PeakRSS,
		Threads:       r.Threads,
		Cgroup: &pb.CgroupResources{
			Note:                    c.Note,
			MemoryCurrentBytes:      c.MemoryCurrent,
			MemoryPeakBytes:         c.MemoryPeak,
			MemoryMaxBytes:          c.MemoryMax,
			MemoryInactiveFileBytes: c.MemoryInactiveFile,
			CpuUsageUsec:            usec(c.CPUUsage),
			CpuUserUsec:             usec(c.CPUUser),
			CpuSystemUsec:           usec(c.CPUSystem),
			CpuQuotaUsec:            usec(c.CPUQuota),
			CpuPeriodUsec:           usec(c.CPUPeriod),
			CpuNrThrottled:          c.NrThrottled,
			CpuThrottledUsec:        usec(c.CPUThrottled),
			Tasks:                   c.Tasks,
			TasksMax:                c.TasksMax,
		},
	}
}

// DescribeNode reports the node's kernel, cgroup layout and container stack.
// Like DescribeProcess it never fails: a fact the agent cannot see comes back
// empty with the note that says why, since the point of the call is to show what
// this agent can and cannot see of its node.
func (s *Server) DescribeNode(_ context.Context, _ *pb.DescribeNodeRequest) (*pb.DescribeNodeResponse, error) {
	n := s.insp.DescribeNode()
	components := make([]*pb.Component, 0, len(n.Components))
	for _, c := range n.Components {
		components = append(components, &pb.Component{
			Name:          c.Name,
			Pid:           c.PID,
			Exe:           c.Exe,
			Cmdline:       c.Cmdline,
			Version:       c.Version,
			VersionSource: c.VersionSource,
			Module:        c.Module,
			GoVersion:     c.GoVersion,
			Note:          c.Note,
		})
	}
	return &pb.DescribeNodeResponse{
		Kernel: &pb.Kernel{
			Release:  n.Kernel.Release,
			Version:  n.Kernel.Version,
			Machine:  n.Kernel.Machine,
			Arch:     n.Kernel.Arch,
			OsImage:  n.Kernel.OSImage,
			OsSource: n.Kernel.OSSource,
		},
		Cgroups: &pb.Cgroups{
			Mode:          n.Cgroups.Mode,
			ModeSource:    n.Cgroups.ModeSource,
			Driver:        n.Cgroups.Driver,
			DriverSource:  n.Cgroups.DriverSource,
			AgentPath:     n.Cgroups.AgentPath,
			ExamplePath:   n.Cgroups.ExamplePath,
			ExamplePid:    n.Cgroups.ExamplePID,
			ExampleComm:   n.Cgroups.ExampleComm,
			Namespaced:    n.Cgroups.Namespaced,
			NamespaceNote: n.Cgroups.NamespaceNote,
		},
		Components: components,
	}, nil
}

// ProbeFeatures reports what the kernel supports for BPF, as bpftool feature
// probe does. It never fails either: a probe the agent could not run comes back
// with the reason in place of an answer.
func (s *Server) ProbeFeatures(_ context.Context, _ *pb.ProbeFeaturesRequest) (*pb.ProbeFeaturesResponse, error) {
	f := s.insp.ProbeFeatures()
	resp := &pb.ProbeFeaturesResponse{
		SysctlNote:         f.SysctlNote,
		KernelConfigSource: f.KernelConfigSource,
		KernelConfigNote:   f.KernelConfigNote,
		BpfSyscall:         f.BPFSyscall,
		ProgramTypes:       featureProbes(f.ProgramTypes),
		MapTypes:           featureProbes(f.MapTypes),
		Misc:               featureProbes(f.Misc),
	}
	for _, c := range f.Sysctls {
		resp.Sysctls = append(resp.Sysctls, &pb.Sysctl{Name: c.Name, Value: c.Value, Readable: c.Readable, Note: c.Note})
	}
	for _, o := range f.KernelConfig {
		resp.KernelConfig = append(resp.KernelConfig, &pb.KernelConfigOption{Name: o.Name, Value: o.Value})
	}
	return resp, nil
}

// CgroupTree lists the cgroups with BPF programs attached, as bpftool cgroup
// tree does.
func (s *Server) CgroupTree(_ context.Context, req *pb.CgroupTreeRequest) (*pb.CgroupTreeResponse, error) {
	tree, err := s.insp.CgroupTree(req.GetRoot(), req.GetEffective())
	if err != nil {
		return nil, err
	}
	resp := &pb.CgroupTreeResponse{MountPoint: tree.MountPoint, Root: tree.Root}
	for _, c := range tree.Cgroups {
		cg := &pb.CgroupAttachments{Path: c.Path, Id: c.ID}
		for _, p := range c.Programs {
			cg.Programs = append(cg.Programs, &pb.CgroupProgram{
				Id:             p.ID,
				AttachType:     p.AttachType,
				AttachFlags:    p.AttachFlags,
				Name:           p.Name,
				AttachBtfName:  p.AttachBTFName,
				AttachBtfObjId: p.AttachBTFObjID,
				AttachBtfId:    p.AttachBTFID,
			})
		}
		resp.Cgroups = append(resp.Cgroups, cg)
	}
	return resp, nil
}

func featureProbes(probes []inspector.Probe) []*pb.FeatureProbe {
	out := make([]*pb.FeatureProbe, 0, len(probes))
	for _, p := range probes {
		out = append(out, &pb.FeatureProbe{Name: p.Name, Available: p.Available, Note: p.Note})
	}
	return out
}

func (s *Server) ListLinks(_ context.Context, _ *pb.ListLinksRequest) (*pb.ListLinksResponse, error) {
	links, err := s.insp.ListLinks()
	if err != nil {
		return nil, err
	}
	resp := &pb.ListLinksResponse{Links: make([]*pb.LinkInfo, 0, len(links))}
	for _, l := range links {
		resp.Links = append(resp.Links, &pb.LinkInfo{
			Id:         l.ID,
			Type:       l.Type,
			ProgId:     l.ProgID,
			Attach:     l.Attach,
			CgroupPath: l.CgroupPath,
		})
	}
	return resp, nil
}
