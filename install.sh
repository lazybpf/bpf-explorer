#!/usr/bin/env bash
# Installs the bpf-explorer binary for running locally (--role=local):
#
#     curl -fsSL https://github.com/lazybpf/bpf-explorer/releases/latest/download/install.sh | bash
#
# Pin a release by passing its tag, or install somewhere else with INSTALL_DIR:
#
#     curl -fsSL .../install.sh | bash -s v0.2.0
#     curl -fsSL .../install.sh | INSTALL_DIR=/usr/local/bin sudo -E bash
#
# The tarball is checked against the release's checksums.txt before anything
# is installed. Everything runs from main, called on the last line, so a
# download cut short by the pipe never executes half a script.
set -euo pipefail

REPO="lazybpf/bpf-explorer"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

die() {
  echo "bpf-explorer install: $*" >&2
  exit 1
}

main() {
  local version="${1:-latest}"

  [[ "$(uname -s)" == "Linux" ]] || die "only Linux is supported, not $(uname -s)"
  command -v curl >/dev/null || die "curl is required"
  command -v sha256sum >/dev/null || die "sha256sum is required"
  command -v tar >/dev/null || die "tar is required"

  local arch
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "no release binary for $(uname -m); build it from source instead" ;;
  esac

  # Asset names carry no version, so latest/download/<name> always resolves.
  local base
  if [[ "$version" == "latest" ]]; then
    base="https://github.com/${REPO}/releases/latest/download"
  else
    base="https://github.com/${REPO}/releases/download/${version}"
  fi
  local asset="bpf-explorer-linux-${arch}.tar.gz"

  # Global, not local: the EXIT trap runs after main has returned.
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  echo "Downloading ${asset} (${version})"
  curl -fsSL -o "$tmp/$asset" "$base/$asset" || die "download failed: $base/$asset"
  curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || die "download failed: $base/checksums.txt"

  # Only the line for our asset, so a missing entry fails rather than passes.
  grep " ${asset}\$" "$tmp/checksums.txt" > "$tmp/want.txt" || die "${asset} is not in checksums.txt"
  (cd "$tmp" && sha256sum --quiet -c want.txt) || die "checksum mismatch for ${asset}"

  tar -xzf "$tmp/$asset" -C "$tmp" bpf-explorer
  mkdir -p "$INSTALL_DIR"
  install -m 0755 "$tmp/bpf-explorer" "$INSTALL_DIR/bpf-explorer"

  echo "Installed $("$INSTALL_DIR/bpf-explorer" --version 2>/dev/null || echo bpf-explorer) to $INSTALL_DIR/bpf-explorer"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "Note: $INSTALL_DIR is not on your PATH; add it in your shell profile." ;;
  esac

  # sudo resets PATH to secure_path, which leaves out ~/.local/bin.
  echo "Run it with: sudo $INSTALL_DIR/bpf-explorer, then browse http://localhost:8080"
}

main "$@"
