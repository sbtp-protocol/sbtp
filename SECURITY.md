# Security policy

SBTP is pre-release software: no version is supported for production use yet.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting: the **Security** tab
of this repository, then **Report a vulnerability**. Never open a public issue, discussion or pull request
for a vulnerability.

When reporting, please include the affected component (`sbtp-core`, relay, a vector, the specification),
the version or commit, a description of the impact, and if possible a minimal block or input that
reproduces it.

## Scope

In scope: the layer 0 decoder and validation (format, `block_id`, proof of work, Ed25519 verification), the
interoperability vectors, the relay, and the specification itself (a flaw in a rule is a vulnerability
too).

## What the project does

- Independent security reviews per milestone, kept in [`docs/security/`](docs/security/).
- Fuzzing of the decoder, strict Ed25519 verification with a mandatory start-up self-test, no `unsafe` code
  in the workspace.
- Supply-chain rules: pinned lock file, crates.io only, a two-week minimum age for every dependency
  version, `cargo deny` checks (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).
