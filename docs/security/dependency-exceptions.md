# Dependency exceptions

Exceptions to the supply-chain rules of `CONTRIBUTING.md` (in particular the two-week minimum age). Each one is
decided by the project owner, justified, reviewed, and listed here. An exception covers only the crate and
versions named; transitive dependencies stay under the rule.

| Date | Crate | Versions | Age at decision | Decided by | Reason | Conditions | Review |
|---|---|---|---|---|---|---|---|
| 2026-11-18 | `redb` | 4.4.0 → 4.6.0 | 4.5.0: 13 days, 4.6.0: 5 days | project owner | 4.6.0 fixes repair opening a damaged database as empty (instead of `Corrupted`), `check_integrity()` wrong at exactly 4 GiB, reads during close returning later commits, exponential-time integrity checks; 4.5.0 adds `Database::close()` returning errors. All relevant to the relay's crash recovery and graceful shutdown. Same sole publisher (`cberner`) for 4.3–4.6, none yanked. | Source diff 4.4.0 → 4.6.0 reviewed by the security reviewer before the bump; only `redb` is bumped; full tests, including kill and recovery tests, pass after the bump | **approved with conditions** (`2026-11-18-redb-4.6-exception.md`): exact pin `=4.6.0`, default features only, lock diff limited to `redb` (checksum `096b1dd5…535ef`), migration test of a 4.4.0-written index (clean and after `kill -9`), backup of `index.redb` before the first 4.6.0 start, kill/recovery tests on the deployment architecture. **Applied 2026-11-19** (merge of `feat/relay-redb-4.6`): lock diff verified, migration of all tables PASS on aarch64 (clean and `kill -9`); x86-64 kill/recovery and migration PASS on the test VM (2026-11-19, no AVX-512 there); AVX-512 path (review F-1) still untested, deferred until the hosting target is known |
