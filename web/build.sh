#!/bin/sh
# Builds sbtp-wasm for the web client into web/pkg/ (not committed). Run from anywhere.
# Needs: cargo with the wasm32-unknown-unknown target, wasm-bindgen CLI 0.2.130 (the same version
# as the wasm-bindgen crate in Cargo.lock), binaryen's wasm-opt. Nothing is downloaded.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/web/pkg"
want=$(grep -A1 '^name = "wasm-bindgen"$' "$root/Cargo.lock" | sed -n 's/^version = "\(.*\)"$/\1/p')
have=$(wasm-bindgen --version | cut -d' ' -f2)
if [ "$want" != "$have" ]; then
  echo "wasm-bindgen CLI $have does not match the crate version $want in Cargo.lock" >&2
  exit 1
fi
# Registry sources and the checkout are compiled from absolute paths, which end up in panic
# locations: remap them to relative names, as crates/sbtp-wasm/npm/build.sh does, so that web/pkg
# names no home directory. Fields of CARGO_ENCODED_RUSTFLAGS are separated by 0x1f, which keeps a
# path with spaces intact. Different flags from a normal build, so a target directory of its own
# (under CARGO_TARGET_DIR when it is set, so that worktrees share it).
cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
CARGO_ENCODED_RUSTFLAGS=$(printf '%s\037%s' \
  "--remap-path-prefix=$cargo_home/registry/src=registry" "--remap-path-prefix=$root=sbtp")
export CARGO_ENCODED_RUSTFLAGS
cargo_target="${CARGO_TARGET_DIR:-"$root/target"}/web-pkg"
cargo build --manifest-path "$root/Cargo.toml" -p sbtp-wasm --target wasm32-unknown-unknown --release \
  --target-dir "$cargo_target"
unset CARGO_ENCODED_RUSTFLAGS
rm -rf "$out"
wasm-bindgen --target web --no-typescript --out-dir "$out" \
  "$cargo_target/wasm32-unknown-unknown/release/sbtp_wasm.wasm"
wasm-opt -Os --strip-debug --strip-producers --strip-target-features \
  "$out/sbtp_wasm_bg.wasm" -o "$out/sbtp_wasm_bg.wasm"
for literal in "${HOME:-}" "$root" "$cargo_home"; do
  [ -z "$literal" ] && continue
  if LC_ALL=C grep -rlaF "$literal" "$out" > /dev/null; then
    echo "web/pkg holds the local path $literal: $(LC_ALL=C grep -rlaF "$literal" "$out" | tr '\n' ' ')" >&2
    exit 1
  fi
done
raw=$(wc -c < "$out/sbtp_wasm_bg.wasm" | tr -d ' ')
gz=$(gzip -9c "$out/sbtp_wasm_bg.wasm" | wc -c | tr -d ' ')
echo "web/pkg/sbtp_wasm_bg.wasm: $raw bytes ($gz gzip -9)"
