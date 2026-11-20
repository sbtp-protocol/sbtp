# Documentation index

| Folder / file | Content | Normative |
|---|---|---|
| [`spec/sbtp-core-v0.2.md`](spec/sbtp-core-v0.2.md) | Layer 0: block format, `block_id`, signature, PoW, relay HTTP API, P2P sync | yes |
| [`spec/architecture.md`](spec/architecture.md) | The three layers, relay design, runtimes | yes (relay design) |
| [`spec/l2-grammar.md`](spec/l2-grammar.md) | Layer 2 payload grammar, `sbtp.*` kinds, sealed envelope, normative CDDL | yes |
| [`spec/graph-access.md`](spec/graph-access.md) | `sbtp:` URI, JSON block view, graph gateway read API, discovery; reference MCP server (§6, non-normative) | yes (except §6) |
| [`decisions/`](decisions/) | Architecture Decision Records | yes (accepted ADRs) |
| [`test-vectors/`](test-vectors/) | Interoperability vectors (`v1/`) and their catalogue | yes |
| [`security/`](security/) | Independent security reviews, one per milestone | no (records) |
| [`benchmarks/`](benchmarks/) | Benchmark records, pre-registrations, the gating VM specification | no (records) |

Precedence when two documents disagree: accepted ADRs, then the specification, then everything else. A
disagreement is a bug: report it as an issue.
