// Package server adapts an *inspector.Inspector to the generated gRPC
// BpfInspectorServer interface. It holds no kernel logic — just translation
// between proto messages and inspector calls.
package server

import (
	"context"

	pb "github.com/lazybpf/bpf-explorer/gen/bpfinspectorv1"
	"github.com/lazybpf/bpf-explorer/internal/inspector"
)

// Server implements pb.BpfInspectorServer.
type Server struct {
	pb.UnimplementedBpfInspectorServer
	insp *inspector.Inspector
}

func New(insp *inspector.Inspector) *Server { return &Server{insp: insp} }

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
