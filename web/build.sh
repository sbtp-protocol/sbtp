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
cargo build --manifest-path "$root/Cargo.toml" -p sbtp-wasm --target wasm32-unknown-unknown --release
rm -rf "$out"
wasm-bindgen --target web --no-typescript --out-dir "$out" \
  "$root/target/wasm32-unknown-unknown/release/sbtp_wasm.wasm"
wasm-opt -Os --strip-debug --strip-producers --strip-target-features \
  "$out/sbtp_wasm_bg.wasm" -o "$out/sbtp_wasm_bg.wasm"
raw=$(wc -c < "$out/sbtp_wasm_bg.wasm" | tr -d ' ')
gz=$(gzip -9c "$out/sbtp_wasm_bg.wasm" | wc -c | tr -d ' ')
echo "web/pkg/sbtp_wasm_bg.wasm: $raw bytes ($gz gzip -9)"
