# Single image carrying the one bpf-explorer binary; the DaemonSet and the UI
# Deployment select behavior with --role=agent|ui. Both pass it explicitly, so
# the binary's --role=local default never applies in-cluster - but it does mean
# running this image with no args starts the all-in-one local process rather
# than exiting on a usage error.
#
# Build (local, native arch):
#     $ docker build -t ghcr.io/lazybpf/bpf-explorer:dev .
#
# Build multi-arch with buildx (TARGETOS/TARGETARCH are set by buildx):
#     $ docker buildx build --platform linux/amd64,linux/arm64 \
#         -t ghcr.io/lazybpf/bpf-explorer:dev .
#
# The binary is pure Go (cilium/ebpf needs no cgo), so we cross-compile from the
# build platform instead of emulating the target — fast even for arm64.

FROM --platform=$BUILDPLATFORM golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH
# Stamped into the binary and shown in the UI header. Left empty for a plain
# `docker build`, in which case the binary reports itself as a dev build.
ARG VERSION=""
ARG COMMIT=""
WORKDIR /src

# Cache module downloads separately from the source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION_PKG=github.com/lazybpf/bpf-explorer/internal/version
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath \
	-ldflags="-s -w -X ${VERSION_PKG}.Version=${VERSION} -X ${VERSION_PKG}.Commit=${COMMIT}" \
	-o /out/bpf-explorer ./cmd/bpf-explorer

# Distroless "static" (root by default). The agent DaemonSet runs privileged as
# root to read BPF objects; the UI Deployment overrides to a non-root user via
# its securityContext (see bpf-explorer.yaml).
FROM gcr.io/distroless/static-debian12:latest

LABEL org.opencontainers.image.title="bpf-explorer" \
      org.opencontainers.image.description="A cluster-wide, read-only web UI for browsing eBPF maps and programs across Kubernetes nodes." \
      org.opencontainers.image.source="https://github.com/lazybpf/bpf-explorer" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /out/bpf-explorer /usr/local/bin/bpf-explorer
ENTRYPOINT ["/usr/local/bin/bpf-explorer"]
