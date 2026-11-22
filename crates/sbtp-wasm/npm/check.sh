#!/bin/sh
# Contents check of the @sbtp/wasm tarball (ADR 0053 rules 35 and 42), run by build.sh and by CI.
#
#   crates/sbtp-wasm/npm/check.sh <sbtp-wasm-VERSION.tgz>
#
# Fails if the tarball holds anything other than the expected files (regular files only), if the
# manifest declares a script, a dependency or other than the expected name, version, licence and
# file list, if any file holds a local or absolute path or a source map reference, or if the module
# is not under the 200,000-byte gzip budget of ADR 0048. Reads the tarball only; extracts nothing to
# disk and executes nothing from it.
set -eu

MAX_WASM_GZIP_BYTES=200000

die() { echo "check.sh: $*" >&2; exit 1; }
[ $# -eq 1 ] || die "usage: check.sh <tarball>"
tgz=$1
[ -f "$tgz" ] || die "no such file: $tgz"
for tool in cargo node tar gzip grep; do
  command -v "$tool" > /dev/null || die "$tool not found in PATH"
done
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
tools="$here/tools.mjs"

# The file list, exactly: npm's own package.json and README.md, plus `files` of package.json.
expected="package/LICENSE-APACHE
package/LICENSE-MIT
package/README.md
package/node.js
package/package.json
package/sbtp_wasm.d.ts
package/sbtp_wasm.js
package/sbtp_wasm_bg.wasm"
listed=$(tar -tzf "$tgz" | LC_ALL=C sort)
if [ "$listed" != "$expected" ]; then
  echo "unexpected file list:" >&2
  printf '%s\n' "$listed" | sed 's/^/  /' >&2
  die "expected exactly: $(printf '%s ' $expected)"
fi
# Regular files only: no directory entry, link or device (the mode string starts with "-").
if tar -tvzf "$tgz" | grep -qv '^-'; then
  die "the tarball holds an entry that is not a regular file"
fi

version=$(cd "$root" && cargo metadata --format-version 1 --no-deps --locked | node "$tools" crate-version)
tar -xOzf "$tgz" package/package.json | node "$tools" manifest "$version"
case "$(basename "$tgz")" in
  "sbtp-wasm-$version.tgz") ;;
  *) die "tarball name $(basename "$tgz") does not carry the crate version $version" ;;
esac

# Local and absolute paths, source maps. The standard library's `/rustc/<commit>/library/...` paths
# are rustc's own remapping and name no machine, so they are not matched.
paths='(^|[^A-Za-z0-9._-])/(Users|home|root|private|tmp|var|opt|usr|srv|mnt|Volumes|nix|runner|github|workspace|build)/|[A-Z]:\\\\?(Users|Windows|runner|a)\\|\.cargo/|\.rustup/|/target/(wasm32|release|debug)|file://|sourceMappingURL'
for f in $expected; do
  hits=$(tar -xOzf "$tgz" "$f" | LC_ALL=C grep -aoE "$paths" | LC_ALL=C sort -u | head -5 || true)
  [ -z "$hits" ] || die "$f holds a local path or source map reference: $(printf '%s ' $hits)"
  for literal in "${HOME:-}" "$root"; do
    [ -z "$literal" ] && continue
    if tar -xOzf "$tgz" "$f" | LC_ALL=C grep -aqF "$literal"; then
      die "$f holds the local path $literal"
    fi
  done
done

raw=$(tar -xOzf "$tgz" package/sbtp_wasm_bg.wasm | wc -c | tr -d ' ')
gz=$(tar -xOzf "$tgz" package/sbtp_wasm_bg.wasm | gzip -9c | wc -c | tr -d ' ')
[ "$gz" -lt "$MAX_WASM_GZIP_BYTES" ] || die "sbtp_wasm_bg.wasm is $gz bytes gzip, budget is below $MAX_WASM_GZIP_BYTES"

echo "contents check passed: $(basename "$tgz")"
tar -tvzf "$tgz" | sed 's/^/  /'
echo "  sbtp_wasm_bg.wasm: $raw bytes, $gz bytes gzip -9 (budget: below $MAX_WASM_GZIP_BYTES)"
