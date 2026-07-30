# bpf-explorer

A cluster-wide, read-only web UI for browsing eBPF maps and programs across
Kubernetes nodes - so you don't have to `kubectl exec` into a per-node
[`bpftool-daemon`](https://github.com/lazybpf/bpftool-daemon) pod to see what's
loaded.

> [!NOTE]
> This is a relatively new project, so there may be some hiccups. If you hit
> one, please [open an issue](https://github.com/lazybpf/bpf-explorer/issues)
> with the build version from the UI header - or `bpf-explorer --version` - e.g.
> `v0.1.0 (0dd5b51)`, plus the output of `kubectl get nodes -o wide`. Kernel
> version, OS image, and container runtime largely decide which BPF objects are
> inspectable at all.

It runs as two components:

- agent (`--role=agent`) - gRPC server in a privileged DaemonSet; reads maps and
  programs via `cilium/ebpf`.
- ui (`--role=ui`) - a Deployment that discovers agents via the Kubernetes API
  and fans out gRPC calls, serving HTML. `ClusterIP` only; reached via
  `kubectl port-forward`.

One binary serves both roles; one image runs both workloads.

In a three-node cluster with an agent on every node:

```mermaid
flowchart LR
    op(["Operator"])

    subgraph cluster["Kubernetes cluster"]
        api["Kubernetes API"]
        ui["ui Deployment<br/>ClusterIP :80 -> :8080"]

        subgraph n1["node-1"]
            a1["agent :50051"]
            k1[("host kernel<br/>maps · progs · links")]
        end

        subgraph n2["node-2"]
            a2["agent :50051"]
            k2[("host kernel")]
        end

        subgraph n3["node-3"]
            a3["agent :50051"]
            k3[("host kernel")]
        end
    end

    op -->|"port-forward, HTTP"| ui
    ui -.->|"list agent pods"| api
    ui -->|gRPC| a1
    ui -->|gRPC| a2
    ui -->|gRPC| a3
    a1 --> k1
    a2 --> k2
    a3 --> k3
```

Images are published to GHCR for `linux/amd64` and `linux/arm64`.

## Quick start

Nothing to clone - label the node(s) you want an agent on and apply the manifest
attached to the latest release:

```console
kubectl label node <node> bpf-explorer=true
```

```console
kubectl apply -f https://github.com/lazybpf/bpf-explorer/releases/latest/download/bpf-explorer.yaml
```

Then port-forward the UI and browse http://localhost:8080:

```console
kubectl -n bpf-explorer port-forward svc/bpf-explorer-ui 8080:80
```

> [!TIP]
> The DaemonSet uses a `nodeSelector` (`bpf-explorer: "true"`) so agents only
> land on labelled nodes. Remove the selector to run on every node.

## Cleanup

```console
kubectl delete namespace bpf-explorer
```

```console
kubectl label node <node> bpf-explorer-
```

## Build

Pure Go - no CGO, and the gRPC stubs in `gen/` are committed, so there is no
codegen step:

```console
go build -o bpf-explorer ./cmd/bpf-explorer
```

Unit tests need no cluster and no privileges:

```console
go test ./...
```

The image. `:dev` is the tag `bpf-explorer.yaml` tracks in this repo, so a local
build drops straight into the manifest:

```console
docker build -t ghcr.io/lazybpf/bpf-explorer:dev .
```

Multi-arch (cross-compiled, no emulation needed):

```console
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/lazybpf/bpf-explorer:dev .
```

## Load into a containerd dev cluster with `ctr`

For a single-node / dev cluster running containerd (k3s, kind's containerd, a
bare kubeadm node), import the image straight into the `k8s.io` namespace so the
kubelet can use it without a registry:

```console
docker save ghcr.io/lazybpf/bpf-explorer:dev -o /tmp/bpf-explorer.tar
sudo ctr -n k8s.io images import /tmp/bpf-explorer.tar && rm /tmp/bpf-explorer.tar
```

Then apply this repo's manifest, which points at `:dev` with
`imagePullPolicy: IfNotPresent`, so the imported image is used as-is:

```console
kubectl apply -f bpf-explorer.yaml
```

## Run locally without a cluster

Point the UI at an agent directly (static discovery), no RBAC needed. Two
terminals - the agent needs BPF privileges:

```console
sudo ./bpf-explorer --role=agent --listen=:50051
```

```console
./bpf-explorer --role=ui --agents=local=localhost:50051
```

Then browse http://localhost:8080.

## Releasing

Pushing an annotated tag is the only way to publish. The
[`publish-image`](.github/workflows/publish-image.yaml) workflow builds the
multi-arch image, pushes it to GHCR under the tag name, and opens a GitHub
release whose notes come from the tag annotation:

```console
git tag -a v0.1.0 -m "v0.1.0 - first release"
git push origin v0.1.0
```

Each release carries a copy of `bpf-explorer.yaml` with the image line rewritten
from `:dev` to that release's tag, so what a cluster runs is always a version
someone tagged. There is no `:latest` image tag - nothing floats.

> [!IMPORTANT]
> Tags and releases are immutable. Nothing can be re-published under a version
> that already shipped, so every fix - however small - goes out as a new tag.

Versions are [semantic](https://semver.org): `vMAJOR.MINOR.PATCH`. Bump PATCH
for fixes, MINOR for backwards-compatible additions, MAJOR for a breaking change
to the manifest or the flags. The gRPC surface between the UI and the agents is
internal - both ship in the same image, so it can change without a MAJOR bump.

### Release candidates

A hyphen makes the tag a pre-release, so bake one before a MINOR or MAJOR bump:

```console
git tag -a v0.2.0-rc.1 -m "v0.2.0-rc.1 - cursor pagination for DumpMap"
git push origin v0.2.0-rc.1
```

Candidates are deliberately quieter than releases:

| Tag | Image | GitHub release |
| --- | ----- | -------------- |
| `v0.2.0-rc.1` | `:v0.2.0-rc.1` | marked pre-release |
| `v0.2.0` | `:v0.2.0` | latest release |

Since `releases/latest/download/` resolves to the newest release that is *not* a
pre-release, an `rc` never becomes what the Quick start installs - test it by
applying its manifest explicitly:

```console
kubectl apply -f https://github.com/lazybpf/bpf-explorer/releases/download/v0.2.0-rc.1/bpf-explorer.yaml
```

Iterate with `-rc.2`, `-rc.3`, ... and cut the final `v0.2.0` from the same
commit as the last candidate once it looks good.

## TODO

- Cursor pagination for `DumpMap`. The proto carries `cursor` / `next_cursor`
  but the server only honours `limit`, so a huge map is truncated rather than
  paged.
- Per-CPU map values. Values of per-CPU map types are rendered as one opaque
  blob instead of a per-CPU slice.
- Informer-based agent discovery. The UI polls the Kubernetes API on each
  page load; a `SharedInformer` would cut refresh latency.
- mTLS between UI and agents. Agent gRPC is plaintext and unauthenticated within
  the namespace; namespace isolation plus a NetworkPolicy is the current fence.

## License

Apache License 2.0 - see [LICENSE](LICENSE).
