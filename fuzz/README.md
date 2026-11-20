# Fuzzing `sbtp-core` and `sbtp-l2`

Two targets.

`decode_block` (`fuzz_targets/decode_block.rs`): `parse`, `validate_submitted`,
`validate_requested` and the staged forms on arbitrary bytes, with several difficulties, with and
without a requested identifier, and a re-signing mode that reaches the accepting path. The first input
byte is a control byte (difficulty and mode); the rest is the candidate block. See the target's header
for the oracles.

`validate_l2` (`fuzz_targets/validate_l2.rs`): the `sbtp-l2` payload decoder (`validate_l2_invariants`,
`cbor::check_profile`, `validate_block`) on arbitrary bytes. The first input byte is a control byte
(number of header parents, and whether the first parent equals the seeds' `block` identifier); the rest
is the candidate payload. Oracles: no panic; an accepted payload passes the profile and
`Payload::encode` returns exactly its bytes; `validate_block` agrees; and a differential against a
lenient CBOR parser shows the profile checker accepts only canonical encodings and accepts every
encoder output. See the target's header.

This directory is a standalone cargo-fuzz workspace (its own `Cargo.lock`), not a member of the main
workspace. It needs the nightly toolchain and `cargo-fuzz`.

## Running it

From the repository root:

```bash
# 1. Seed the corpus from the frozen vectors (docs/test-vectors/v1/): every vector behind each mode's
#    control byte, written to fuzz/corpus/decode_block/ (gitignored; another directory can be
#    given as the last argument). The vector files are checked first, read-only.
cargo run -p sbtp-core --features vector-gen --example gen_vectors -- --fuzz-seeds

# 2. Fuzz. -max_len=66200 lets inputs reach the maximum block (65,909 bytes) and F2 (65,910);
#    libFuzzer's default of 4,096 bytes would cut both off.
cargo +nightly fuzz run decode_block -- -max_len=66200 -dict=fuzz/decode_block.dict -max_total_time=300
```

For `validate_l2`, the seeds are committed in `fuzz/seeds/validate_l2/` (one valid payload per kind,
taken from the `sbtp-l2` tests, behind its control byte). Pass them as a second, read-only corpus
directory so new inputs go to the gitignored `fuzz/corpus/validate_l2/`:

```bash
# Regenerate or verify the seeds after a change to the sbtp-l2 payload format.
cargo run --manifest-path fuzz/Cargo.toml --example validate_l2_seeds             # write
cargo run --manifest-path fuzz/Cargo.toml --example validate_l2_seeds -- --check  # verify

mkdir -p fuzz/corpus/validate_l2
cargo +nightly fuzz run validate_l2 fuzz/corpus/validate_l2 fuzz/seeds/validate_l2 -- \
    -dict=fuzz/validate_l2.dict -max_len=66000 -max_total_time=300
```

`-max_len=66000` lets inputs reach the largest payload (65,535 bytes) and one byte more.

Step 1 matters: without seeds, a random input carries the magic and version with probability 2^-24, so
an unseeded run stays on F1 and F3 whatever its execution count (review 2026-11-18 M2, F-2).

`fuzz/corpus/` and `fuzz/artifacts/` are gitignored. A crash leaves its input in
`fuzz/artifacts/<target>/`; replay it with `cargo +nightly fuzz run <target> <file>`, turn it
into a regression test in `crates/sbtp-core/tests/` or `crates/sbtp-l2/tests/`, and do not commit the artifact itself.

Keep `CUSTOM_LIBFUZZER_PATH` unset: `libfuzzer-sys` would link that prebuilt library instead of
compiling its bundled sources.
