// Package server adapts an *inspector.Inspector to the generated gRPC
// BpfInspectorServer interface. It holds no kernel logic — just translation
// between proto messages and inspector calls.
package server

import (
	"context"
	"time"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
	"github.com/lazybpf/bpf-explorer/internal/inspector"
	"github.com/lazybpf/bpf-explorer/internal/tracelog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements pb.BpfInspectorServer.
type Server struct {
	pb.UnimplementedBpfInspectorServer
	insp *inspector.Inspector
	hub  *tracelog.Hub
}

func New(insp *inspector.Inspector, hub *tracelog.Hub) *Server {
	return &Server{insp: insp, hub: hub}
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
			Id:         m.ID,
			Name:       m.Name,
			Type:       m.Type,
			KeySize:    m.KeySize,
			ValueSize:  m.ValueSize,
			MaxEntries: m.MaxEntries,
			Flags:      m.Flags,
			Dumpable:   m.Dumpable,
			DumpNote:   m.DumpNote,
			Pids:       pids,
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
			KeyHex:   e.KeyHex,
			KeyFmt:   e.KeyFmt,
			ValueHex: e.ValueHex,
			ValueFmt: e.ValueFmt,
		})
	}
	return resp, nil
}

func (s *Server) ListPrograms(_ context.Context, _ *pb.ListProgramsRequest) (*pb.ListProgramsResponse, error) {
	progs, err := s.insp.ListPrograms()
	if err != nil {
		return nil, err
	}
	resp := &pb.ListProgramsResponse{Programs: make([]*pb.ProgramInfo, 0, len(progs))}
	for _, p := range progs {
		pids := make([]*pb.ProcessRef, 0, len(p.PIDs))
		for _, ref := range p.PIDs {
			pids = append(pids, &pb.ProcessRef{Pid: ref.PID, Comm: ref.Comm})
		}
		resp.Programs = append(resp.Programs, &pb.ProgramInfo{
			Id:     p.ID,
			Name:   p.Name,
			Type:   p.Type,
			Tag:    p.Tag,
			MapIds: p.MapIDs,
			Pids:   pids,
		})
	}
	return resp, nil
}

func (s *Server) DumpProgram(_ context.Context, req *pb.DumpProgramRequest) (*pb.DumpProgramResponse, error) {
	dump, err := s.insp.DumpProgram(req.GetId())
	if err != nil {
		return nil, err
	}
	return &pb.DumpProgramResponse{
		Lines:     dump.Lines,
		Available: dump.Available,
		Note:      dump.Note,
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
	return &pb.DescribeProcessResponse{
		Found:   d.Found,
		Pid:     d.PID,
		Comm:    d.Comm,
		State:   d.State,
		Ppid:    d.PPID,
		Uid:     d.UID,
		Cmdline: d.Cmdline,
		Exe:     d.Exe,
		Cgroup:  d.Cgroup,
	}, nil
}

func (s *Server) ListLinks(_ context.Context, _ *pb.ListLinksRequest) (*pb.ListLinksResponse, error) {
	links, err := s.insp.ListLinks()
	if err != nil {
		return nil, err
	}
	resp := &pb.ListLinksResponse{Links: make([]*pb.LinkInfo, 0, len(links))}
	for _, l := range links {
		resp.Links = append(resp.Links, &pb.LinkInfo{
			Id:     l.ID,
			Type:   l.Type,
			ProgId: l.ProgID,
			Attach: l.Attach,
		})
	}
	return resp, nil
}
