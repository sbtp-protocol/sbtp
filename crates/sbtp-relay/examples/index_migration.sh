#!/usr/bin/env bash
# redb upgrade check of the relay index (docs/security/2026-11-18-redb-4.6-exception.md, condition 3).
#
# Usage: crates/sbtp-relay/examples/index_migration.sh [BASE_REV]
#
# BASE_REV is the commit that still pins the old redb (default: afe1911, the last `main` commit on
# redb 4.4.0). The script exports BASE_REV into a temporary directory, adds `index_migration.rs` from
# the current tree to it, and builds both versions of the example. All index files live in that
# temporary directory, removed at exit (KEEP=1 keeps it); nothing is written to the repository's
# data directories and no fixture is committed.
#
# Checks, each comparing the summary line (row count, epoch, last position, digest of every row):
#   1. clean:     written and closed cleanly by the old version, opened by the new one;
#   2. kill -9:   killed by the old version mid-load; one copy opened (repaired) by the old version,
#                 another by the new one: both must see the same state;
#   3. downgrade: each file opened by the new version is reopened by the old one (informative for
#                 the rollback path; condition 4 still asks for a backup copy).
set -euo pipefail

BASE_REV="${1:-afe1911}"
BLOCKS="${BLOCKS:-20000}"
repo="$(git rev-parse --show-toplevel)"
work="$(mktemp -d "${TMPDIR:-/tmp}/sbtp-index-migration.XXXXXX")"
loader=""
cleanup() {
    if [ -n "$loader" ]; then kill -9 "$loader" 2>/dev/null || true; fi
    if [ "${KEEP:-0}" = 1 ]; then echo "kept: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT

redb_version() { awk '/^name = "redb"$/ { getline; print $3 }' "$1/Cargo.lock" | tr -d '"'; }

mkdir -p "$work/old"
git -C "$repo" archive "$BASE_REV" | tar -x -C "$work/old"
cp "$repo/crates/sbtp-relay/examples/index_migration.rs" "$work/old/crates/sbtp-relay/examples/"
echo "old tree: $(git -C "$repo" rev-parse --short "$BASE_REV"), redb $(redb_version "$work/old")"
echo "new tree: $(git -C "$repo" rev-parse --short HEAD) + working tree, redb $(redb_version "$repo")"

(cd "$work/old" && cargo build --locked -q -p sbtp-relay --example index_migration --target-dir "$work/target-old")
(cd "$repo" && cargo build --locked -q -p sbtp-relay --example index_migration --target-dir "$work/target-new")
old="$work/target-old/debug/examples/index_migration"
new="$work/target-new/debug/examples/index_migration"

fail=0
check() { # label expected got
    if [ "$2" = "$3" ]; then echo "PASS $1: $3"; else echo "FAIL $1: expected '$2', got '$3'"; fail=1; fi
}

# 1. Clean shutdown.
mkdir "$work/clean"
written="$("$old" write "$work/clean/index.redb" "$BLOCKS")"
check "clean, 4.4 reopen" "$written" "$("$old" inspect "$work/clean/index.redb")"
check "clean, new open" "$written" "$("$new" inspect "$work/clean/index.redb")"
check "clean, new reopen" "$written" "$("$new" inspect "$work/clean/index.redb")"
check "clean, downgrade" "$written" "$("$old" inspect "$work/clean/index.redb")"

# 2. kill -9 during writes.
mkdir "$work/kill"
"$old" load "$work/kill/index.redb" > "$work/kill/out" 2>&1 &
loader=$!
loader_died() { # message
    echo "FAIL $1; loader output:"
    cat "$work/kill/out"
    loader=""
    exit 1
}
for _ in $(seq 1 300); do
    grep -q LOADING "$work/kill/out" && break
    kill -0 "$loader" 2>/dev/null || loader_died "loader exited before LOADING"
    sleep 0.1
done
grep -q LOADING "$work/kill/out" || loader_died "loader never reached LOADING"
sleep 0.3 # still inserting: the kill lands mid-load, between durable commits
kill -0 "$loader" 2>/dev/null || loader_died "loader exited before the kill"
kill -9 "$loader"
wait "$loader" 2>/dev/null || true
loader=""
echo "killed mid-load: $(cat "$work/kill/out")"
cp -p "$work/kill/index.redb" "$work/kill/old.redb"
cp -p "$work/kill/index.redb" "$work/kill/new.redb"
repaired="$("$old" inspect "$work/kill/old.redb")"
check "kill -9, new open" "$repaired" "$("$new" inspect "$work/kill/new.redb")"
check "kill -9, new reopen" "$repaired" "$("$new" inspect "$work/kill/new.redb")"
check "kill -9, downgrade" "$repaired" "$("$old" inspect "$work/kill/new.redb")"
case "$repaired" in rows=0\ *) echo "FAIL kill -9: nothing survived"; fail=1 ;; esac

exit "$fail"
