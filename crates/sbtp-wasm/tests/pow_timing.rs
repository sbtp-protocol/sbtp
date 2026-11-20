//! Mining time through the binding API, in slices of 2^16 attempts as a Web Worker would mine.
//! Native only: it gives the baseline the browser measure (Q-28) is compared to. Ignored by default;
//! run with
//! `cargo test -p sbtp-wasm --release --test pow_timing -- --ignored --nocapture`.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]

use std::time::{Duration, Instant};

use sbtp_wasm::{build_unsigned, mine_slice};

const SLICE: u64 = 1 << 16;
const RUNS: u64 = 40;

fn mine_once(difficulty: u32, salt: u64) -> Duration {
    let mut block = build_unsigned(&[0x11; 32], salt, 0, &[], &salt.to_be_bytes()).unwrap();
    let start = Instant::now();
    while mine_slice(&mut block, difficulty, SLICE).unwrap().is_none() {}
    start.elapsed()
}

#[test]
#[ignore = "timing, run on demand"]
fn pow_time_at_16_and_20() {
    for difficulty in [16, 20] {
        let mut times: Vec<Duration> = (0..RUNS).map(|salt| mine_once(difficulty, salt)).collect();
        times.sort();
        let median = times[times.len() / 2];
        let p95 = times[(times.len() * 95) / 100 - 1];
        let mean = times.iter().sum::<Duration>() / u32::try_from(times.len()).unwrap();
        println!(
            "d = {difficulty}: {RUNS} runs, median {median:?}, mean {mean:?}, p95 {p95:?}, max {:?}",
            times.last().unwrap()
        );
    }
}
