# VM specification for the ADR 0013 gating benchmark (for the operator of the test machine)

Purpose: run the redb index gate of ADR 0013 on the environment its protocol requires. Decision: project
owner, 2026-11-18 (a virtual machine provisioned for the purpose). The VM is disposable.

## Machine

| Item | Requirement | Why |
|---|---|---|
| Architecture | x86-64 (KVM, CPU type `host` or `x86-64-v3`) | Protocol target `x86_64-unknown-linux-musl` |
| OS | Debian 13 or Ubuntu 24.04 LTS, minimal, up to date | Plain Linux with `/proc/<pid>/status` (`VmHWM`) |
| vCPU | 4 | Harness runs 8 client threads; avoids CPU starvation skewing timings |
| RAM | 8 GiB | Headroom: the measured process is expected well under 12 MiB, the page cache is not |
| Swap | **none** (no swap partition, no swapfile, no zram) | Required by the protocol: swap would hide resident memory |
| Disk | 60 GiB, SSD-backed, **ext4** (or XFS), single root filesystem | Data sets up to 0.8 GB, redb file up to about 4.3 GB, build target about 2 GB |
| Kernel settings | defaults; `vm.overcommit_memory` default; no cgroup memory limit on the benchmark user | Measure, do not constrain |
| Time | NTP enabled (systemd-timesyncd or chrony) | Reception times and TTL steps use the wall clock |

## Software

- `build-essential`, `musl-tools`, `git`, `curl`, `time` (GNU time, `/usr/bin/time -v`).
- Rust via rustup, installed for the benchmark user only:
  - toolchain stable 1.100 (the repo's `rust-toolchain.toml` selects stable);
  - targets `x86_64-unknown-linux-musl` and the host default.
- Nothing else. No Docker needed.

## Network and security

- Isolated VLAN or bridge with no access to the LAN management networks (hypervisor, firewall, cluster).
- Outbound HTTPS only, and only during setup and the build: `static.rust-lang.org`, `sh.rustup.rs`,
  `crates.io`, `index.crates.io`, `static.crates.io`. It can be cut once `cargo fetch --locked` has run.
- Inbound: SSH only, key-based, from the operator workstation. One unprivileged user `bench` with no sudo
  after setup.
- **No secrets on the VM:** no API keys, no Git credentials, no SSH agent forwarding. The repository has no
  remote: the code arrives as a `git bundle` copied over SSH and is verified against the expected commit
  hash.
- Snapshot after setup (clean baseline). Destroy the VM after the gate, or roll back to the snapshot.

## Run conditions

- The gate runs the relay with profile `small` and `rate_limit_exempt = ["127.0.0.1/32"]`: its 8 loopback
  clients would otherwise sit exactly at `max_connections_per_client = 8` (ADR 0019).
- No other heavy workload on the same host during the runs, at least none sharing the VM's cores
  or disk. Write down what else was running if that cannot be guaranteed.
- The benchmark is run by the implementer per the ADR 0013 protocol as clarified by ADR 0017 (accepted
  2026-11-18; pre-registration principle: no change after results are known).
- ADR 0017 changes no requirement of this document. The relay and the load generator are two processes
  of the user `bench` on this one VM, talking over loopback HTTP: no second VM, no open port. The same
  user reads `/proc/<pid>/status` of the relay. The 4 vCPUs are shared by the relay and the 8 generator
  clients; only the relay process is measured.

## First measurement on the VM (before the gate)

Run `query_diag` (branch `diag/relay-query-memory`, see `docs/benchmarks/2026-11-18-query-memory-diagnosis.md`)
built for `x86_64-unknown-linux-musl`, with the default 8 clients and no bound, and read `VmHWM`. It tells
whether the macOS memory growth exists with musl's allocator at all; then repeat with `index_max_readers` 2
and 4. Informative only (ADR 0017 rule 2), but it decides whether the bound is a fix or defence in depth.

Also run there, on the x86-64 CPU (redb 4.6.0 exception, condition 5 and finding F-1, AVX-512 checksum path): the index kill/recovery tests (`cargo test -p sbtp-relay index::tests`, including `flusher_makes_a_quiet_tail_durable`) and the migration check `crates/sbtp-relay/examples/index_migration.sh`; record whether the CPU has `avx512f` (`grep -m1 -o avx512f /proc/cpuinfo`).

## What the operator hands back

The VM's address, SSH user, OS and kernel version, CPU model as seen by the guest, `free -h` (showing 0 swap),
`findmnt /` (showing ext4/XFS), `rustc -Vv`, `rustup target list --installed`, and the snapshot name.
