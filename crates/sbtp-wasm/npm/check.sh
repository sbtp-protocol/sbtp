#!/bin/sh
# Contents check of the @sbtp/wasm tarball (ADR 0053 rules 35 and 42), run by build.sh and by CI.
#
#   crates/sbtp-wasm/npm/check.sh <sbtp-wasm-VERSION.tgz>
#
# Fails if:
#   - the archive is not in the exact form npm pack writes, or holds anything other than the
#     expected files (regular files only, each once);
#   - the manifest declares a script, a dependency or other than the expected name, version,
#     licence and file list;
#   - a file copied from the repository (manifest, Node.js entry, README, licences) is not
#     byte-identical to its repository copy;
#   - the package exceeds its size bounds, or the module is not under the 200,000-byte gzip budget
#     of ADR 0048;
#   - the type declarations name a DOM-only type or lost the SigningMessage brand;
#   - any file holds a local or absolute path or a source map reference.
# Reads the tarball only; extracts nothing to disk and executes nothing from it.
set -eu

MAX_WASM_GZIP_BYTES=200000
# Bounds of the whole package: the tarball file and the sum of its unpacked files. About twice the
# current sizes (0.1.0: 140 kB packed, 340 kB unpacked), so that only a gross change trips them.
MAX_TARBALL_BYTES=300000
MAX_UNPACKED_BYTES=1000000

die() { echo "check.sh: $*" >&2; exit 1; }
[ $# -eq 1 ] || die "usage: check.sh <tarball>"
tgz=$1
[ -f "$tgz" ] || die "no such file: $tgz"
for tool in cargo node gzip grep cmp; do
  command -v "$tool" > /dev/null || die "$tool not found in PATH"
done
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
tools="$here/tools.mjs"

# The archive is read by tools.mjs only, the way npm reads it (security review 2026-11-22, L-1): one
# gzip member and nothing after it, ustar regular files of mode 0644, exactly the files of
# tools.mjs PACKAGE_FILES (npm's own package.json and README.md, plus `files` of package.json),
# each once, then zero bytes only. tar(1) is not used: it can stop at a lone zero block where npm
# reads on.
listing=$(node "$tools" tar-list "$tgz") || die "the archive is not in the form npm pack writes"
names=$(printf '%s\n' "$listing" | cut -d' ' -f2 | LC_ALL=C sort)
cat_file() { node "$tools" tar-cat "$tgz" "$1"; }

version=$(cd "$root" && cargo metadata --format-version 1 --no-deps --locked | node "$tools" crate-version)
cat_file package/package.json | node "$tools" manifest "$version"
# The files copied verbatim into the package are byte-identical to the repository copies, so no key
# of the manifest and no line of the Node.js entry can differ from what was reviewed (security review
# 2026-11-22, L-2). Only the build output (glue, declarations, module) is not compared here; the
# reproducible build checks it (rebuild and compare the tarball's SHA-256).
for pair in "package.json:$here/package.json" "node.js:$here/node.js" "README.md:$here/README.md" \
  "LICENSE-MIT:$root/LICENSE-MIT" "LICENSE-APACHE:$root/LICENSE-APACHE"; do
  name=${pair%%:*}
  copy=${pair#*:}
  cat_file "package/$name" | cmp -s - "$copy" \
    || die "package/$name differs from the repository copy ${copy#"$root"/}"
done

packed=$(wc -c < "$tgz" | tr -d ' ')
[ "$packed" -le "$MAX_TARBALL_BYTES" ] || die "the tarball is $packed bytes, the bound is $MAX_TARBALL_BYTES"
unpacked=$(printf '%s\n' "$listing" | awk '{ n += $1 } END { print n + 0 }')
[ "$unpacked" -le "$MAX_UNPACKED_BYTES" ] || die "the files of the tarball sum to $unpacked bytes, the bound is $MAX_UNPACKED_BYTES"

# The declarations compile without the "dom" lib and keep the SigningMessage brand.
cat_file package/sbtp_wasm.d.ts | node "$tools" dts-check
case "$(basename "$tgz")" in
  "sbtp-wasm-$version.tgz") ;;
  *) die "tarball name $(basename "$tgz") does not carry the crate version $version" ;;
esac

# Local and absolute paths, source maps. The standard library's `/rustc/<commit>/library/...` paths
# are rustc's own remapping and name no machine, so they are not matched.
paths='(^|[^A-Za-z0-9._-])/(Users|home|root|private|tmp|var|opt|usr|srv|mnt|Volumes|nix|runner|github|workspace|build)/|[A-Z]:\\\\?(Users|Windows|runner|a)\\|\.cargo/|\.rustup/|/target/(wasm32|release|debug)|file://|sourceMappingURL'
for f in $names; do
  hits=$(cat_file "$f" | LC_ALL=C grep -aoE "$paths" | LC_ALL=C sort -u | head -5 || true)
  [ -z "$hits" ] || die "$f holds a local path or source map reference: $(printf '%s ' $hits)"
  for literal in "${HOME:-}" "$root"; do
    [ -z "$literal" ] && continue
    if cat_file "$f" | LC_ALL=C grep -aqF "$literal"; then
      die "$f holds the local path $literal"
    fi
  done
done

raw=$(printf '%s\n' "$listing" | awk '$2 == "package/sbtp_wasm_bg.wasm" { print $1 }')
gz=$(cat_file package/sbtp_wasm_bg.wasm | gzip -9c | wc -c | tr -d ' ')
[ "$gz" -lt "$MAX_WASM_GZIP_BYTES" ] || die "sbtp_wasm_bg.wasm is $gz bytes gzip, budget is below $MAX_WASM_GZIP_BYTES"

echo "contents check passed: $(basename "$tgz")"
printf '%s\n' "$listing" | awk '{ printf "  %9d  %s\n", $1, $2 }'
echo "  package: $packed bytes, $unpacked bytes unpacked (bounds: $MAX_TARBALL_BYTES, $MAX_UNPACKED_BYTES)"
echo "  sbtp_wasm_bg.wasm: $raw bytes, $gz bytes gzip -9 (budget: below $MAX_WASM_GZIP_BYTES)"
