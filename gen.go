//go:build tools

package tools

// Regenerate gRPC/protobuf stubs into ./gen/bpfinspectorv1. This file is behind
// the `tools` build tag, so pass it to the generator:
//
//	go generate -tags tools ./...
//
//go:generate protoc --go_out=. --go_opt=module=github.com/lazybpf/bpf-explorer --go-grpc_out=. --go-grpc_opt=module=github.com/lazybpf/bpf-explorer proto/bpfinspector.proto
