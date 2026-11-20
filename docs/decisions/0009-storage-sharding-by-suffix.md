# 0009: Flat-file storage sharded by the trailing bytes of the `block_id`

- Status: accepted (by the project owner, 2026-11-18)
- Amended by: 0025 (rule 2 and the "Distribution" consequence: one shard level of 256 directories created at start-up)
- Date: 2026-11-18
- Decision: project owner, 2026-11-18
- Questions: Q-12 (partially); security review finding B-6 (second note)
- Impact: `docs/spec/architecture.md` §2 ("Content-addressed storage"); `sbtp-relay` (storage path); no
  `sbtp-core` change; no test vector

## Context

`architecture.md` §2 spreads block files by `block_id` prefix: `/data/blocks/ab/cd/abcd1234…ef.bin`.

The proof of work requires `d` leading zero bits in the `block_id` (spec §3.3). With `d ≥ 16`, the first
two bytes of every stored `block_id` are `00 00`: every file lands in `/data/blocks/00/00/`. The sharding
has no effect. The security review reported it (finding B-6).

## Decision

1. A relay that stores blocks as flat files MUST derive the shard directories from the trailing bytes
   (suffix) of the `block_id`. It MUST NOT derive them from the leading bytes.
2. Layout, with `id` the 32 bytes of the `block_id` and `hex` in lowercase:

   ```
   /data/blocks/<hex(id[31])>/<hex(id[30])>/<hex(id[0..32])>.bin
   ```

   Example for the `block_id` `0000a3…17cdef`: `/data/blocks/ef/cd/0000a3…17cdef.bin`.
3. The file name is the full `block_id` (64 hexadecimal characters), not a truncated form.
4. The on-disk layout is internal to a relay. It is not part of the protocol: no client, peer or mirror may
   depend on it. Blocks are exchanged through the relay interface (spec §4) only.

## Consequences

- **Distribution.** The PoW constrains only the `d` leading bits. The other bits of a BLAKE3 output are
  uniform. With two levels of one byte, blocks spread over 65,536 directories for any `d ≤ 240`.
- **`sbtp-relay`.** Only the path function changes. A lookup stays O(1): the path is computed from the
  `block_id`, with no index.
- **Atomic "first write wins" (B-6, first note).** Not changed by this ADR and still required: ADR 0003
  rule 9 forbids replacing stored bytes, and `rename()` overwrites its target. The final file MUST be
  created exclusively (`create_new`, or `link` from a temporary file). ADR 0008 rule 6 relies on it.
- **Targeted directories.** A sender can grind the nonce so that its blocks fall into one chosen directory.
  Each such block costs `2^16` times the PoW work. Modern file systems index large directories; the effect
  is a slower directory, not a failure. No countermeasure is specified.
- **Tools.** A shell listing sorted by path no longer groups blocks by `block_id` prefix. Nothing in the
  protocol relies on such an order.
- **Static mirrors (tier 3).** A mirror serves `/sbtp/v1/block/{block_id}`; it does not expose the shard
  layout (rule 4).
- **`sbtp-core`.** No change.
- **Compatibility.** No relay is deployed; no migration.

## What this ADR resolves and what stays open

| Question | Resolved here | Still open |
|---|---|---|
| Q-12 | Shard key of the flat-file store (suffix). | `parent → children` index and time index needed by `/query` (embedded key-value store, or append-only log rebuilt at startup); explicit eviction sweeper; storage of chunks (ADR 0010). |

## Rejected alternatives

- **Prefix sharding (status quo).** One directory under PoW.
- **Skip the first `d` bits and shard on the next bytes.** The layout would depend on the difficulty, a
  setting that can change (ADR 0007).
- **Shard on a second hash of the `block_id`, or on a hash keyed by a relay secret.** Removes directory
  targeting, but adds a computation and a secret for a low risk. The trailing bytes are already uniform.
- **No sharding.** Works on modern file systems, but makes listing, backup and deletion tools slow on large
  stores.
- **Embedded database for the blocks themselves.** Out of scope: the owner keeps flat files. The index
  question stays open under Q-12.

## Spec change

Applied to `docs/spec/architecture.md` on 2026-11-18. No change to `docs/spec/sbtp-core-v0.2.md`.

**§2, "Content-addressed storage".** Replace the code block and the first bullet with:

````markdown
```
/data/blocks/
└── ef/                      last byte of the block_id (hex)
    └── cd/                  second-to-last byte
        └── 0000a3…17cdef.bin
```
- Raw binary files, named by the full `block_id` (lowercase hex). A relay MUST derive the shard
  directories from the trailing bytes of the `block_id`, never from the leading bytes: the proof of work
  sets the leading bits to zero. The layout is internal to a relay and is not part of the protocol.
  (ADR 0009)
- The final file is created exclusively, so that "first write wins" holds under concurrency
  (`sbtp-core-v0.2.md` §3.4).
````

The last bullet (`parent → children` index, `[Q-12]`) is unchanged.
