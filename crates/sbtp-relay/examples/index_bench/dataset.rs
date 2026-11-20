#![allow(clippy::indexing_slicing)] // bench-only, see main.rs

//! Deterministic data sets of the ADR 0013 benchmark: fixed seeds, public test key, valid blocks
//! (signature included, difficulty 0), 200-byte payloads.
//!
//! Output, in the data set directory:
//! - `blocks.bin`: the 1,000,000 blocks of step 1; `blocks2.bin`: the 10,000 blocks of the second
//!   load (step 5). Each block is a big-endian `u16` length followed by its bytes.
//! - `parents.bin`: the parents queried in steps 2, 4 and 5, with their children (see [`Sampled`]).

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

use sbtp_core::layout::MAX_PARENTS;
use sbtp_core::{BlockBuilder, BlockId, SigningKey};

/// Blocks loaded in step 1.
pub const BLOCKS: u32 = 1_000_000;
/// Blocks of the second load, killed in step 5.
pub const BLOCKS2: u32 = 10_000;
/// Public seed of the test key. Never a real key.
const KEY_SEED: [u8; 32] = *b"sbtp-relay-bench-public-test-key";
const BASE_TIMESTAMP: u64 = 1_795_000_000_000;
const PAYLOAD_LEN: usize = 200;
/// Typical data set: parents are drawn among this many most recent earlier blocks.
const WINDOW: u32 = 10_000;
/// One queried parent per this many step-1 blocks.
const SAMPLE_EVERY: u32 = 1_000;

/// The two data sets of the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// 20% of blocks with 0 parents, 50% with 1, 30% with 2.
    Typical,
    /// `MAX_PARENTS` distinct random parents per block (the format maximum, ADR 0013 as amended
    /// by ADR 0014), none of them a stored block.
    Adversarial,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "typical" => Some(Self::Typical),
            "adversarial" => Some(Self::Adversarial),
            _ => None,
        }
    }

    const fn seed(self) -> u64 {
        match self {
            Self::Typical => 0x5b70_0001,
            Self::Adversarial => 0x5b70_0002,
        }
    }
}

/// splitmix64: small, deterministic, good enough for workload generation.
pub struct Rng(u64);

impl Rng {
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n > 0`; the modulo bias is irrelevant here).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next_u64().to_be_bytes();
            chunk.copy_from_slice(bytes.get(..chunk.len()).unwrap_or(&[]));
        }
    }
}

/// A queried parent and its children: (data set index, `block_id`), in data set order.
pub struct Sampled {
    pub parent: BlockId,
    pub children: Vec<(u32, BlockId)>,
}

fn invalid(e: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

/// Writes the data set `kind` into `dir`.
pub fn generate(kind: Kind, dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let key = SigningKey::from_bytes(&KEY_SEED);
    let mut rng = Rng::new(kind.seed());
    let mut out = BufWriter::new(File::create(dir.join("blocks.bin"))?);
    let mut out2 = BufWriter::new(File::create(dir.join("blocks2.bin"))?);
    let mut recent = vec![BlockId([0; 32]); WINDOW as usize];
    let mut sampled: Vec<Sampled> = Vec::new();
    // Typical: data set index of a sampled parent → its slot in `sampled`.
    let mut slot: HashMap<u32, usize> = HashMap::new();
    let mut payload = [0u8; PAYLOAD_LEN];
    let mut parents: Vec<BlockId> = Vec::with_capacity(usize::from(MAX_PARENTS));
    let mut parent_idx: Vec<u32> = Vec::with_capacity(2);

    for i in 0..BLOCKS + BLOCKS2 {
        parents.clear();
        parent_idx.clear();
        match kind {
            Kind::Typical => {
                let wanted = match rng.below(10) {
                    0..=1 => 0,
                    2..=6 => 1,
                    _ => 2,
                };
                let window = i.min(WINDOW);
                while parent_idx.len() < wanted.min(window as usize) {
                    let j = i - 1 - u32::try_from(rng.below(u64::from(window))).map_err(invalid)?;
                    if !parent_idx.contains(&j) {
                        parent_idx.push(j);
                        parents.push(recent[(j % WINDOW) as usize]);
                    }
                }
            }
            Kind::Adversarial => {
                while parents.len() < usize::from(MAX_PARENTS) {
                    let mut p = [0u8; 32];
                    rng.fill(&mut p);
                    if !parents.contains(&BlockId(p)) {
                        parents.push(BlockId(p));
                    }
                }
            }
        }
        rng.fill(&mut payload);
        let block = BlockBuilder::for_key(&key)
            .timestamp(BASE_TIMESTAMP + u64::from(i))
            .parents(&parents)
            .payload(&payload)
            .build(&key, 0)
            .map_err(invalid)?;
        let id = sbtp_core::parse(&block).map_err(invalid)?.block_id();
        recent[(i % WINDOW) as usize] = id;

        let sample = i < BLOCKS && i % SAMPLE_EVERY == 0;
        match kind {
            Kind::Typical => {
                for j in &parent_idx {
                    if let Some(&s) = slot.get(j) {
                        sampled[s].children.push((i, id));
                    }
                }
                if sample {
                    slot.insert(i, sampled.len());
                    sampled.push(Sampled {
                        parent: id,
                        children: Vec::new(),
                    });
                }
            }
            Kind::Adversarial if sample => {
                sampled.push(Sampled {
                    parent: parents[0],
                    children: vec![(i, id)],
                });
            }
            Kind::Adversarial => {}
        }

        let w = if i < BLOCKS { &mut out } else { &mut out2 };
        w.write_all(&u16::try_from(block.len()).map_err(invalid)?.to_be_bytes())?;
        w.write_all(&block)?;
    }
    out.flush()?;
    out2.flush()?;

    let mut p = BufWriter::new(File::create(dir.join("parents.bin"))?);
    p.write_all(&u32::try_from(sampled.len()).map_err(invalid)?.to_be_bytes())?;
    for s in &sampled {
        p.write_all(s.parent.as_bytes())?;
        p.write_all(
            &u32::try_from(s.children.len())
                .map_err(invalid)?
                .to_be_bytes(),
        )?;
        for (idx, id) in &s.children {
            p.write_all(&idx.to_be_bytes())?;
            p.write_all(id.as_bytes())?;
        }
    }
    p.flush()
}

pub fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn read_id(r: &mut impl Read) -> io::Result<BlockId> {
    let mut b = [0u8; 32];
    r.read_exact(&mut b)?;
    Ok(BlockId(b))
}

/// Reads `parents.bin`.
pub fn read_sampled(dir: &Path) -> io::Result<Vec<Sampled>> {
    let mut r = BufReader::new(File::open(dir.join("parents.bin"))?);
    let n = read_u32(&mut r)?;
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let parent = read_id(&mut r)?;
        let k = read_u32(&mut r)?;
        let mut children = Vec::with_capacity(k as usize);
        for _ in 0..k {
            children.push((read_u32(&mut r)?, read_id(&mut r)?));
        }
        out.push(Sampled { parent, children });
    }
    Ok(out)
}

/// Reads the next length-prefixed block into `buf`; `false` at the end of the file.
pub fn read_block(r: &mut impl Read, buf: &mut Vec<u8>) -> io::Result<bool> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(e) => return Err(e),
    }
    buf.resize(usize::from(u16::from_be_bytes(len)), 0);
    r.read_exact(buf)?;
    Ok(true)
}
