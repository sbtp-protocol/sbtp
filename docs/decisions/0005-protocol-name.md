# 0005: Protocol name

- Status: accepted (by the project owner, 2026-11-18)
- Date: 2026-11-18
- Questions: Q-15
- Impact: documentation; no crate, no test vector

## Context

The original documents use four expansions of the acronym SBTP:

| Name | Source |
|---|---|
| Signed Block Transport Protocol | doc 01 (specification), Drive folder |
| Secure Block Transport Protocol | doc 02 |
| Simple Block Transfer/Transport Protocol | docs 03 and 04 |
| Sovereign Block Transfer Protocol | economic study |

The repository (`CLAUDE.md`, `docs/spec/`, `Cargo.toml`, crates) already uses the first one everywhere. The
other names survive only in the Drive documents, which are no longer authoritative.

The name appears in the domain separation strings of ADR 0002 as the acronym `SBTP`: the acronym must be
frozen before the first test vectors.

## Decision

1. The protocol name is **Signed Block Transport Protocol**. Its acronym is **SBTP**.
2. Every document in the repository MUST use this name and no other expansion of the acronym.
3. The acronym `SBTP`, the magic bytes `SB`, the URL prefix `/sbtp/v1/` and the crate prefix `sbtp-` are
   unchanged.
4. A text derived from an original document (study, grant application, publication) MUST be corrected
   before distribution (see also Q-18).

## Consequences

- No change to format, size or offset. `layout.rs` is not touched.
- No file in the repository needs correcting: a search for the three other names in `docs/` and `crates/`
  returns no match (except the open questions (not published), which quotes them).
- "Signed" describes a verifiable property of every block. "Transport" matches the role of layer 0.
- To be checked by the project owner, outside the scope of this ADR: availability of the name and acronym
  (trademarks, domain names, crate name `sbtp` on crates.io, namesakes in other protocols).

## Rejected alternatives

- **Secure Block Transport Protocol.** "Secure" is a general, unverifiable promise, and suggests a
  confidentiality the protocol does not offer (Q-17).
- **Simple Block Transfer/Transport Protocol.** "Simple" is a judgement, not a description. Two variants
  already coexist.
- **Sovereign Block Transfer Protocol.** Positioning vocabulary, specific to the economic study, with no link
  to a technical property.
- **Change the acronym.** Nothing justifies it; the acronym is already in the magic bytes and the URL paths.

## Spec change

No change to `docs/spec/sbtp-core-v0.2.md`: its title already carries the chosen name.

On acceptance, add to the status box at the top of the spec, after the line about `[Q-xx]` references:

```markdown
> Protocol name: *Signed Block Transport Protocol*, acronym SBTP (ADR 0005).
```
