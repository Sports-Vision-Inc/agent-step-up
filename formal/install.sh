#!/usr/bin/env bash
# Install the provers into formal/bin/ (gitignored).
#  - Tamarin: Linux x86_64 release binary from GitHub releases (latest), or on
#    macOS `brew install tamarin-prover/tap/tamarin-prover` (pulls Maude too).
#  - Maude: GitHub release binary; falls back to the distro package
#    (`apt-get install maude`, Ubuntu 24.04 ships 3.2, which this repo's Maude
#    models were run with).
# Network access to api.github.com / github.com release assets is required for
# the Tamarin download. In the environment where results.json was produced this
# access was blocked by egress policy, so Tamarin results there are "not_run".
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/bin"
mkdir -p "$BIN"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
OS="$(uname -s)"; ARCH="$(uname -m)"

asset_url() {  # $1 = owner/repo, $2 = grep -E pattern for the asset name
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" \
    | grep -Eo '"browser_download_url": *"[^"]+"' | cut -d'"' -f4 | grep -E "$2" | head -n1
}

if [[ "$OS" == "Darwin" ]]; then
  echo "macOS: run  brew install tamarin-prover/tap/tamarin-prover  (installs maude too)"
  command -v brew >/dev/null && brew install tamarin-prover/tap/tamarin-prover || true
  exit 0
fi
if [[ "$ARCH" != "x86_64" ]]; then
  echo "Only Linux x86_64 release binaries are fetched automatically; build Tamarin from source." >&2
fi

# --- Tamarin ---
if [[ ! -x "$BIN/tamarin-prover" ]]; then
  if url="$(asset_url tamarin-prover/tamarin-prover 'linux64.*\.tar\.gz$')" && [[ -n "$url" ]]; then
    echo "downloading $url"
    curl -fsSL "$url" -o "$TMP/tamarin.tar.gz"
    tar -xzf "$TMP/tamarin.tar.gz" -C "$TMP"
    install -m 0755 "$(find "$TMP" -type f -name tamarin-prover | head -n1)" "$BIN/tamarin-prover"
  else
    echo "WARNING: could not reach GitHub releases for tamarin-prover; Tamarin jobs will be not_run." >&2
  fi
fi

# --- Maude ---
if [[ ! -x "$BIN/maude" ]] && ! command -v maude >/dev/null; then
  if url="$(asset_url maude-lang/Maude 'Linux.*x86_64.*\.zip$|linux.*\.zip$')" && [[ -n "$url" ]]; then
    echo "downloading $url"
    curl -fsSL "$url" -o "$TMP/maude.zip"
    (cd "$TMP" && python3 -m zipfile -e maude.zip maude_x)
    m="$(find "$TMP/maude_x" -type f \( -name 'maude' -o -name 'maude.linux64' -o -name 'maude.linux' \) | head -n1)"
    install -m 0755 "$m" "$BIN/maude"
    # prelude files must sit next to the binary
    find "$(dirname "$m")" -maxdepth 1 -name '*.maude' -exec cp {} "$BIN/" \;
  elif command -v apt-get >/dev/null; then
    echo "falling back to apt-get install maude"
    (sudo -n true 2>/dev/null && sudo apt-get install -y maude) || apt-get install -y maude
  else
    echo "WARNING: could not install maude" >&2
  fi
fi

echo "tamarin: $( (PATH="$BIN:$PATH" tamarin-prover --version 2>/dev/null | head -n1) || echo missing)"
echo "maude:   $( (PATH="$BIN:$PATH" maude --version 2>/dev/null) || echo missing)"
