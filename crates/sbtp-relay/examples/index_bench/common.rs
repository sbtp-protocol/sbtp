//! Helpers shared by the `index_bench` and `query_diag` tools (included by path in both). Bench
//! only, never in the relay.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dataset::Rng;

/// Relay clock: Unix milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Resident size of this process now, in bytes, from `ps` (0 if `ps` gives nothing).
pub fn rss_bytes() -> std::io::Result<u64> {
    let pid = std::process::id().to_string();
    let ps = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()?;
    let kib: u64 = String::from_utf8_lossy(&ps.stdout)
        .trim()
        .parse()
        .unwrap_or(0);
    Ok(kib * 1024)
}

/// `VmHWM` of this process in bytes (Linux `/proc/self/status`); `None` elsewhere.
pub fn vmhwm_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kib: u64 = line
        .trim_start_matches("VmHWM:")
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kib * 1024)
}

/// One query of the step-2 mix of ADR 0013.
pub enum Mix {
    /// By parent: index into the list of queried parents.
    Parent(usize),
    /// No parent: this `since`, in milliseconds.
    Since(u64),
}

/// Query number `q` of the mix: even ones by parent (uniform among `parents` values), odd ones by
/// `since` (uniform over `t0..=t1`). Deterministic in `q`, whatever client runs it.
pub fn mix(q: u64, parents: usize, t0: u64, t1: u64) -> Mix {
    let mut rng = Rng::new(0x9e37_79b9 ^ q.wrapping_mul(0x0100_0000_01b3));
    if q.is_multiple_of(2) {
        let n = u64::try_from(parents.max(1)).unwrap_or(u64::MAX);
        Mix::Parent(usize::try_from(rng.below(n)).unwrap_or(0))
    } else {
        Mix::Since(t0 + rng.below(t1.saturating_sub(t0) + 1))
    }
}
