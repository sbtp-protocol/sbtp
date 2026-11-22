#!/bin/sh
# Installs an @sbtp/wasm tarball into a new scratch project, with scripts disabled and nothing
# fetched from a registry, and runs smoke.mjs there with Node.js.
#
#   crates/sbtp-wasm/npm/smoke.sh <sbtp-wasm-VERSION.tgz>
set -eu
die() { echo "smoke.sh: $*" >&2; exit 1; }
[ $# -eq 1 ] || die "usage: smoke.sh <tarball>"
[ -f "$1" ] || die "no such file: $1"
tgz=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)

scratch=$(mktemp -d "${TMPDIR:-/tmp}/sbtp-wasm-smoke.XXXXXX")
echo '{ "name": "sbtp-wasm-smoke", "private": true, "type": "module" }' > "$scratch/package.json"
: > "$scratch/.npmrc-empty"
(cd "$scratch" && npm_config_ignore_scripts=true NPM_CONFIG_USERCONFIG="$scratch/.npmrc-empty" \
  npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false \
  npm install --ignore-scripts --offline --no-audit --no-fund --save-exact "$tgz")
cp "$here/smoke.mjs" "$scratch/smoke.mjs"
(cd "$scratch" && node smoke.mjs)
echo "scratch project left in $scratch"
