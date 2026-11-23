# Fuzzing `sbtp-core`

One target, `decode_block` (`fuzz_targets/decode_block.rs`): `parse`, `validate_submitted`,
`validate_requested` and the staged form on arbitrary bytes, at several difficulties, with and without
a requested identifier, plus a re-signing mode that reaches the accepting path. The first input byte is
a control byte (difficulty and mode); the rest is the candidate block. The oracles are in the target's
header.

This directory is a standalone cargo-fuzz workspace (its own `Cargo.lock`). It needs the nightly
toolchain and `cargo-fuzz`. From the repository root:

```bash
# -max_len=66200 lets inputs reach the largest block (65,909 bytes) and F2 (65,910).
cargo +nightly fuzz run decode_block -- -max_len=66200 -dict=fuzz/decode_block.dict -max_total_time=300
```

Seeds: each frozen vector's `block_hex` behind a control byte of `0x00`, written to the gitignored
`fuzz/corpus/decode_block/`.
