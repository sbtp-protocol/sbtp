#!/bin/sh
# Builds the npm package @sbtp/wasm (ADR 0053 rules 26, 27 and 35) and packs it into a tarball.
#
#   crates/sbtp-wasm/npm/build.sh [--allow-dirty] [OUT_DIR]      (OUT_DIR defaults to dist-npm/)
#
# Steps: check the pinned tool versions; build the release module with the default features (`l2`
# and `seal`); wasm-bindgen --target web and wasm-opt -Os with the flags of web/build.sh; assemble
# the package in target/npm/package/; `npm pack` with scripts disabled; run check.sh on the tarball;
# print its SHA-256 and its integrity string.
#
# Reproducibility (Q-79): every tool is pinned below, the tree must be clean (the tarball is then the
# build of one commit), local paths are remapped out of the module (`--remap-path-prefix`), and npm pack
# writes fixed timestamps. Nothing is downloaded and nothing from the package is executed.
set -eu

# Pinned tools. rustc is pinned by rust-toolchain.toml and wasm-bindgen by Cargo.lock (the CLI must
# match the crate). Node.js and npm are pinned because npm pack writes the tarball.
WASM_OPT_VERSION=133
NODE_VERSION=v22.23.4
NPM_VERSION=10.9.9
# The WebAssembly features of the module (target_features of the cargo output), from which the
# README derives the minimum browser versions (ADR 0053 rule 29). A change here is a README change.
FEATURES="+bulk-memory +bulk-memory-opt +call-indirect-overlong +multivalue +mutable-globals +nontrapping-fptoint +reference-types +sign-ext"

die() { echo "build.sh: $*" >&2; exit 1; }

allow_dirty=0
if [ "${1:-}" = "--allow-dirty" ]; then allow_dirty=1; shift; fi
case "${1:-}" in -h|--help) sed -n '2,13p' "$0"; exit 0 ;; esac

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:-"$root/dist-npm"}
mkdir -p "$out"
out=$(cd "$out" && pwd)
stage="$root/target/npm/package"
tools="$here/tools.mjs"

# --- Source -----------------------------------------------------------------------------------
commit=$(git -C "$root" rev-parse HEAD)
if [ -n "$(git -C "$root" status --porcelain)" ]; then
  [ "$allow_dirty" = 1 ] || die "the working tree is not clean (commit or stash first, or pass --allow-dirty for a local test build)"
  commit="$commit-dirty"
fi

# --- Tool versions ----------------------------------------------------------------------------
want_rustc=$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$root/rust-toolchain.toml")
have_rustc=$(cd "$root" && rustc --version | cut -d' ' -f2)
[ "$want_rustc" = "$have_rustc" ] || die "rustc $have_rustc, rust-toolchain.toml pins $want_rustc"
want_bindgen=$(grep -A1 '^name = "wasm-bindgen"$' "$root/Cargo.lock" | sed -n 's/^version = "\(.*\)"$/\1/p')
have_bindgen=$(wasm-bindgen --version | cut -d' ' -f2)
[ "$want_bindgen" = "$have_bindgen" ] || die "wasm-bindgen CLI $have_bindgen, Cargo.lock has $want_bindgen"
have_opt=$(wasm-opt --version | sed -n 's/^wasm-opt version \([0-9][0-9]*\).*/\1/p')
[ "$have_opt" = "$WASM_OPT_VERSION" ] || die "wasm-opt version ${have_opt:-unknown}, pinned $WASM_OPT_VERSION (binaryen)"
have_node=$(node --version)
[ "$have_node" = "$NODE_VERSION" ] || die "Node.js $have_node, pinned $NODE_VERSION"
have_npm=$(npm --version)
[ "$have_npm" = "$NPM_VERSION" ] || die "npm $have_npm, pinned $NPM_VERSION"

version=$(cd "$root" && cargo metadata --format-version 1 --no-deps --locked | node "$tools" crate-version)

# --- Module -----------------------------------------------------------------------------------
# Registry sources are compiled from absolute paths under CARGO_HOME, which end up in panic
# locations; remap them, and the checkout, to relative names. Different flags from a normal build,
# so a target directory of its own. Fields of CARGO_ENCODED_RUSTFLAGS are separated by 0x1f, which
# keeps a path with spaces intact.
cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
CARGO_ENCODED_RUSTFLAGS=$(printf '%s\037%s' \
  "--remap-path-prefix=$cargo_home/registry/src=registry" "--remap-path-prefix=$root=sbtp")
export CARGO_ENCODED_RUSTFLAGS
cargo_target="$root/target/npm/cargo"
cargo build --manifest-path "$root/Cargo.toml" -p sbtp-wasm --target wasm32-unknown-unknown \
  --release --locked --target-dir "$cargo_target"
unset CARGO_ENCODED_RUSTFLAGS
module="$cargo_target/wasm32-unknown-unknown/release/sbtp_wasm.wasm"

have_features=$(node "$tools" features "$module")
[ "$have_features" = "$FEATURES" ] || die "module features changed: $have_features (README minimum browser versions to update, then FEATURES)"

# --- Package ----------------------------------------------------------------------------------
rm -rf "$stage"
wasm-bindgen --target web --out-dir "$stage" "$module"
# Declarations of the raw exports; sbtp_wasm.d.ts already carries them (InitOutput).
rm -f "$stage/sbtp_wasm_bg.wasm.d.ts"
# The init API is typed with DOM lib names; replace them by local aliases so that the declarations
# compile for a consumer without the "dom" lib (tools.mjs dts-fix, checked again by check.sh).
node "$tools" dts-fix "$stage/sbtp_wasm.d.ts"
wasm-opt -Os --strip-debug --strip-producers --strip-target-features \
  "$stage/sbtp_wasm_bg.wasm" -o "$stage/sbtp_wasm_bg.wasm"
cp "$here/package.json" "$here/README.md" "$here/node.js" "$stage/"
cp "$root/LICENSE-MIT" "$root/LICENSE-APACHE" "$stage/"
chmod 0644 "$stage"/*
node "$tools" manifest "$version" < "$stage/package.json"

tarball="$out/sbtp-wasm-$version.tgz"
rm -f "$tarball"
# Scripts disabled (there are none), no user or global npm configuration read, nothing fetched.
: > "$root/target/npm/empty-user-npmrc"
: > "$root/target/npm/empty-global-npmrc"
(cd "$stage" && npm_config_ignore_scripts=true NPM_CONFIG_USERCONFIG="$root/target/npm/empty-user-npmrc" \
  NPM_CONFIG_GLOBALCONFIG="$root/target/npm/empty-global-npmrc" \
  npm_config_update_notifier=false npm_config_fund=false \
  npm pack --ignore-scripts --json --pack-destination "$out") > "$root/target/npm/pack.json"
packed=$(node "$tools" pack-integrity < "$root/target/npm/pack.json")
[ "${packed%% *}" = "sbtp-wasm-$version.tgz" ] || die "npm pack wrote ${packed%% *}"

# --- Check and report -------------------------------------------------------------------------
sh "$here/check.sh" "$tarball"
integrity=$(node "$tools" digest "$tarball" | sed -n 's/^integrity //p')
[ "$integrity" = "${packed#* }" ] || die "npm pack reported ${packed#* }, the file hashes to $integrity"

echo
echo "source commit  $commit"
echo "tools          rustc $have_rustc, wasm-bindgen $have_bindgen, wasm-opt $have_opt, node $have_node, npm $have_npm"
echo "tarball        $tarball"
node "$tools" digest "$tarball"
