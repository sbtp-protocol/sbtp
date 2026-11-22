//! Relay settings (ADR 0018 rules 6 to 8 and 22, as amended by ADR 0019; ADR 0007; ADR 0012 rules 8
//! and 23; ADR 0013).
//!
//! Effective value of a setting, lowest to highest precedence (ADR 0019 rule 36): built-in default,
//! value of the chosen `profile` (rule 37), TOML file (`--config <path>` or `SBTP_RELAY_CONFIG`),
//! environment variable `SBTP_RELAY_<NAME>`. A bad value is an error that names the setting;
//! nothing is clamped, ignored or adjusted (ADR 0018 rule 7, ADR 0019 rule 36.4).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use axum::http::HeaderValue;

use crate::index;
use crate::log::{ClientTag, Format, Level, Timestamp};
use crate::peers::{PeerUrl, ReplicationStart};
use zeroize::Zeroizing;

/// `max_query_limit`: default and maximum, the index clamp (ADR 0012 rule 8, ADR 0018 rule 14).
const MAX_QUERY_LIMIT: u64 = index::MAX_QUERY_LIMIT as u64;
/// `index_cache_bytes` default (ADR 0013 rule 24).
const DEFAULT_INDEX_CACHE_BYTES: u64 = index::DEFAULT_INDEX_CACHE_BYTES as u64;
/// The largest TOML integer, `2^63 - 1`: the file and the environment accept the same values
/// (ADR 0019 rule 5).
const TOML_MAX: u64 = (1 << 63) - 1;
/// `block_ttl_ms`: 0 (eviction disabled) or this value to the maximum (ADR 0019 rules 4 and 6).
const MIN_BLOCK_TTL_MS: u64 = 60_000;
/// `stats_interval_ms`: 0 (off) or this value to the maximum (ADR 0021 rule 46).
const MIN_STATS_INTERVAL_MS: u64 = 10_000;
/// The smallest `rate_block_burst`: the largest weight of ADR 0051 rule 21 (a batch of 256
/// identifiers, `⌈256/4⌉`). Rule 21 caps a weight at the burst, so a smaller burst would serve
/// more than 4 blocks per token (security review 2026-11-21, L-1).
const MIN_BLOCK_BURST: u64 = (crate::batch::MAX_IDS as u64).div_ceil(4);
/// The smallest `rate_query_burst`: the weight of a grouped query of 32 parents, `⌈32/8⌉`.
const MIN_QUERY_BURST: u64 = (crate::query::MAX_PARENTS as u64).div_ceil(8);
/// The default of `min_pow_difficulty`: the network difficulty `D_NET` (ADR 0045 rules 1 and 2).
const NETWORK_POW: u64 = sbtp_core::NETWORK_POW_DIFFICULTY as u64;

/// Prefix of every environment variable of a setting (ADR 0018 rule 6).
pub const ENV_PREFIX: &str = "SBTP_RELAY_";
/// Environment variable naming the configuration file.
pub const ENV_CONFIG: &str = "SBTP_RELAY_CONFIG";

/// The least `max_blocking_threads`, also its default (ADR 0018 rule 19): the block readers, the
/// `PUT` permits and 2 spare threads; when replication runs, also `replication_max_in_flight + 1`
/// (security review 2026-11-21 L-1: the DNS lookups of its connections and its cursor writes wait
/// on blocking threads, so a peer whose DNS answers slowly cannot take the threads of `GET` and
/// `PUT`).
/// ADR 0050: the archive copy's lanes resolve names and write their cursor on blocking threads
/// too, so `mirror_max_in_flight + 1` is added the same way when it runs (`mirror` is 0 when off).
fn blocking_floor(readers: u64, puts: u64, replication: bool, in_flight: u64, mirror: u64) -> u64 {
    let base = readers + puts + 2 + if mirror > 0 { mirror + 1 } else { 0 };
    if replication {
        base + in_flight + 1
    } else {
        base
    }
}

/// Rule 35 estimates, in bytes. Replaced by measures after the Linux gate.
const EST_BASELINE: u64 = 2_621_440;
const EST_LARGEST_RESPONSE: u64 = 70 * 1024;
const EST_READ_WORKING_SET: u64 = 100 * 1024;
/// ADR 0027 clarification T1: one limiter entry, its map element in a map at most half full (two
/// buckets per key, each with its control byte) and two elements of the order of full times
/// (B-tree nodes about half full). Guarded by a `size_of` test in `limiter.rs`.
pub(crate) const EST_LIMITER_ENTRY: u64 = 192;
/// ADR 0049 rule 15: one entry of the network group table (`ingest.rs`), with the formula of ADR
/// 0027 clarification T1 (map element of 40 bytes in a map at most half full, two order elements
/// of 32 bytes): at most 146 bytes. Guarded by a `size_of` test in `ingest.rs`.
pub(crate) const EST_GROUP_ENTRY: u64 = 160;
/// ADR 0049 rule 15: the global bucket and the two counters of rule 6.
const EST_INGEST_FIXED: u64 = 64;
/// ADR 0049 rule 14: the smallest `ingest_bytes_per_hour` other than 0 (off).
const MIN_INGEST_BYTES_PER_HOUR: u64 = 1_048_576;
/// One key of a per-client count table (`client::Counts`): a `(ClientKey, u32)` bucket of 24
/// bytes, its control byte, and a table at most half full after growth. Not measured.
const EST_CLIENT_COUNT_ENTRY: u64 = 64;
/// ADR 0050 rule 27, estimates: one upload in flight (a block, the TLS and HTTP state), and the
/// uploader's window of four pages (`mirror::WINDOW`, 96 bytes a slot, guarded by a `size_of`
/// test) plus the page read into it (64 entries of 48 bytes). Rule 27's 64 × 32 counted one page
/// of identifiers; the window lets the lanes pass a block in back-off.
const EST_MIRROR_PER_REQUEST: u64 = 65_909 + 90_000;
const EST_MIRROR_WINDOW: u64 = 4 * 64 * 96 + 64 * 48;
/// ADR 0052 rule 21: per deny list entry, a 32-byte value and its kind in a table at most half
/// full; two lists are held during a reload.
pub(crate) const EST_DENY_ENTRY: u64 = 80;
/// ADR 0021 rule 21: the log queue, 256 lines of at most 1,024 bytes.
const LOG_QUEUE_BYTES: u64 = (crate::log::QUEUE_LINES * crate::log::MAX_LINE) as u64;

/// One integer setting: its name, value slot, range and built-in default (`None`: computed from
/// the effective values, ADR 0019 rule 36.3).
struct IntSlot<'a> {
    name: &'static str,
    value: &'a mut Option<u64>,
    min: u64,
    max: u64,
    default: Option<u64>,
}

// Integer settings: name, minimum, maximum, built-in default (ADR 0018 rule 22 table; ADR 0007;
// ADR 0012 rule 8; ADR 0013; ADR 0019 rules 1, 4, 5 and 28). The defaults of the settings that a
// profile sets are its `small` column (ADR 0019 rule 36.5). Ranges that depend on another setting
// are checked as constraints.
macro_rules! int_settings {
    ($($name:ident: $min:expr, $max:expr, $default:expr;)*) => {
        #[derive(Default)]
        struct Ints { $($name: Option<u64>,)* }
        const INT_NAMES: &[&str] = &[$(stringify!($name)),*];
        impl Ints {
            fn slot(&mut self, key: &str) -> Option<IntSlot<'_>> {
                match key {
                    $(stringify!($name) => Some(IntSlot {
                        name: stringify!($name),
                        value: &mut self.$name,
                        min: $min,
                        max: $max,
                        default: $default,
                    }),)*
                    _ => None,
                }
            }
        }
    };
}

int_settings! {
    // ADR 0045 rule 2: the default is `D_NET`.
    min_pow_difficulty: 0, 256, Some(NETWORK_POW);
    max_future_ms: 1_000, 86_400_000, Some(300_000);
    max_query_limit: 1, MAX_QUERY_LIMIT, Some(MAX_QUERY_LIMIT);
    // ADR 0046 rule 1: no eviction by age by default.
    block_ttl_ms: 0, 315_360_000_000, Some(0);
    // ADR 0025 rule 16: the tree charge alone is 1,060,864 bytes.
    max_store_bytes: 4_194_304, TOML_MAX, Some(1 << 30);
    sweep_interval_ms: 1_000, 3_600_000, Some(60_000);
    sweep_batch: 1, 1_000, Some(1_000);
    index_cache_bytes: 1_048_576, TOML_MAX, Some(DEFAULT_INDEX_CACHE_BYTES);
    worker_threads: 1, 256, None;
    max_blocking_threads: 1, 512, None;
    max_connections: 1, 65_535, Some(32);
    max_connections_per_client: 1, 65_535, Some(8);
    max_connection_age_ms: 1_000, 86_400_000, Some(300_000);
    max_requests_per_connection: 1, 1_000_000, Some(1_000);
    max_header_bytes: 8_192, 65_536, Some(16_384);
    header_timeout_ms: 1_000, 60_000, Some(5_000);
    body_timeout_ms: 1_000, 120_000, Some(10_000);
    request_timeout_ms: 1_000, 300_000, Some(15_000);
    idle_timeout_ms: 1_000, 600_000, Some(30_000);
    index_max_readers: 1, 64, Some(DEFAULT_INDEX_MAX_READERS);
    index_max_queue: 0, 4_096, Some(32);
    block_max_readers: 1, 256, Some(4);
    block_max_queue: 0, 4_096, Some(32);
    put_max_in_flight: 1, 1_024, Some(4);
    put_max_queue: 0, 4_096, Some(16);
    put_max_in_flight_per_client: 1, 1_024, Some(2);
    queue_timeout_ms: 100, 10_000, Some(1_000);
    shed_retry_after_s: 1, 3_600, Some(2);
    rate_block_per_min: 1, 1_000_000, Some(3_000);
    rate_block_burst: 1, 1_000_000, Some(200);
    rate_query_per_min: 1, 1_000_000, Some(300);
    rate_query_burst: 1, 1_000_000, Some(20);
    rate_put_per_min: 1, 1_000_000, Some(30);
    rate_put_burst: 1, 1_000_000, Some(20);
    rate_limit_max_clients: 64, 16_777_216, Some(4_096);
    client_ipv6_prefix: 32, 64, Some(64);
    block_cache_bytes: 0, TOML_MAX, Some(2 << 20);
    // ADR 0021 rules 23 and 46.
    log_rate_per_min: 6, 6_000, Some(60);
    log_burst: 16, 3_000, Some(120);
    stats_interval_ms: 0, 86_400_000, Some(300_000);
    // ADR 0046 rule 24. The low-water bound below the high-water mark is a constraint.
    demand_high_water_pct: 50, 99, Some(90);
    demand_low_water_pct: 10, 98, Some(80);
    demand_epoch_ms: 14_400_000, 2_592_000_000, Some(28_800_000);
    demand_touch_max: 1_024, 16_777_216, Some(16_384);
    // ADR 0048 rule 15: profile rows, then policy settings.
    replication_max_peers: 1, 256, Some(4);
    replication_max_in_flight: 1, 64, Some(1);
    replication_blocks_per_min: 1, 1_000_000, Some(600);
    replication_bytes_per_hour: 1 << 20, 1 << 40, Some(256 << 20);
    replication_poll_ms: 1_000, 3_600_000, Some(10_000);
    replication_request_timeout_ms: 1_000, 300_000, Some(30_000);
    replication_max_backoff_s: 1, 86_400, Some(3_600);
    replication_resync_margin_ms: 0, 86_400_000, Some(3_600_000);
    // ADR 0049 rule 14. `ingest_bytes_per_hour` is 0 (off) or at least 1 MiB, and
    // `ingest_group56_share_pct` at most `ingest_group_share_pct`: constraints.
    ingest_bytes_per_hour: 0, 1_099_511_627_776, Some(209_715_200);
    ingest_group_max: 64, 16_777_216, Some(1_024);
    ingest_group_share_pct: 1, 100, Some(25);
    ingest_group56_share_pct: 1, 100, Some(10);
    // ADR 0050 rule 28: a profile row, then policy settings.
    // 4 on `small`, not ADR 0050's 1: one lane copied about 25 blocks/s against a LAN MinIO
    // (36 ms per PUT), below a sustained 50 blocks/s of ingest; 4 kept the lag under 1 s.
    mirror_max_in_flight: 1, 64, Some(4);
    mirror_request_timeout_ms: 1_000, 300_000, Some(30_000);
    mirror_max_backoff_s: 1, 86_400, Some(3_600);
    // ADR 0052 rule 21: a profile row, then a policy setting.
    deny_max_entries: 1, 16_777_216, Some(2_048);
    deny_reload_ms: 1_000, 3_600_000, Some(10_000);
    // ADR 0054 rule 30: profile rows, then policy settings. `ws_max_connections` is at most
    // `⌊max_connections / 2⌋` and `ws_max_connections_per_client` at most `ws_max_connections`:
    // constraints.
    ws_max_connections: 1, 32_767, Some(16);
    ws_max_connections_per_client: 1, 32_767, Some(4);
    ws_max_subscriptions: 1, 64, Some(4);
    ws_group_share_pct: 1, 100, Some(25);
    ws_ping_interval_ms: 5_000, 120_000, Some(30_000);
    ws_max_age_ms: 60_000, 86_400_000, Some(3_600_000);
}

/// ADR 0019 rule 37: the settings a profile sets, and no others, with their `standard` and
/// `large` values. The `small` column is the built-in default of `int_settings!` (rule 36.5).
/// `max_blocking_threads` is computed from them (rule 36.3). A change here is a new ADR.
const PROFILE_VALUES: [(&str, [u64; 2]); 31] = [
    ("max_connections", [256, 4_096]),
    ("max_connections_per_client", [16, 32]),
    ("index_max_queue", [128, 256]),
    ("block_max_readers", [8, 16]),
    ("block_max_queue", [128, 256]),
    ("put_max_in_flight", [16, 32]),
    ("put_max_queue", [64, 128]),
    ("put_max_in_flight_per_client", [4, 8]),
    ("rate_block_per_min", [6_000, 12_000]),
    ("rate_block_burst", [400, 600]),
    ("rate_query_per_min", [600, 1_200]),
    ("rate_query_burst", [40, 60]),
    ("rate_put_per_min", [120, 600]),
    ("rate_put_burst", [60, 300]),
    ("rate_limit_max_clients", [32_768, 262_144]),
    ("block_cache_bytes", [32 << 20, 512 << 20]),
    ("index_cache_bytes", [32 << 20, 256 << 20]),
    // ADR 0021 rule 23.
    ("log_rate_per_min", [300, 1_200]),
    ("log_burst", [300, 600]),
    // ADR 0046 rule 24 (amends rule 37).
    ("demand_touch_max", [131_072, 1_048_576]),
    // ADR 0048 rule 15 (amends rule 37).
    ("replication_max_peers", [16, 64]),
    ("replication_max_in_flight", [4, 16]),
    ("replication_blocks_per_min", [3_000, 12_000]),
    ("replication_bytes_per_hour", [2 << 30, 16 << 30]),
    // ADR 0049 rule 14 (amends rule 37).
    ("ingest_bytes_per_hour", [2_147_483_648, 17_179_869_184]),
    ("ingest_group_max", [16_384, 131_072]),
    // ADR 0050 rule 28 (amends rule 37).
    ("mirror_max_in_flight", [4, 8]),
    // ADR 0052 rule 21 (amends rule 37).
    ("deny_max_entries", [65_536, 1_048_576]),
    // ADR 0054 rule 30 (amends rule 37).
    ("ws_max_connections", [128, 2_048]),
    ("ws_max_connections_per_client", [8, 16]),
    ("ws_max_subscriptions", [8, 8]),
];

/// `profile` (ADR 0019 rule 35).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// 1 vCPU, 1 GB; Raspberry Pi; desktop daemon. The default.
    Small,
    /// 2 to 4 vCPU, 4 GB.
    Standard,
    /// 8 vCPU, 16 GB.
    Large,
}

impl Profile {
    /// The name used in the file and the environment.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Standard => "standard",
            Self::Large => "large",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::Small, Self::Standard, Self::Large]
            .into_iter()
            .find(|p| p.name() == s)
    }

    /// The value of `setting` in this profile, if the profile sets it (rule 37).
    #[must_use]
    pub fn value(self, setting: &str) -> Option<u64> {
        let (_, [standard, large]) = PROFILE_VALUES.iter().find(|(n, _)| *n == setting)?;
        match self {
            Self::Small => Ints::default().slot(setting)?.default,
            Self::Standard => Some(*standard),
            Self::Large => Some(*large),
        }
    }
}

/// Where the effective value of a setting comes from (ADR 0019 rule 36.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Built-in default, or computed from the effective values.
    Default,
    /// The chosen profile.
    Profile,
    /// The configuration file.
    File,
    /// An environment variable.
    Env,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default => "default",
            Self::Profile => "profile",
            Self::File => "file",
            Self::Env => "env",
        })
    }
}

/// Non-integer settings.
const OTHER_KEYS: [&str; 29] = [
    "profile",
    "listen",
    "data_dir",
    "cors_allow_origins",
    "rate_limit_exempt",
    "trusted_proxies",
    "log_format",
    "log_level",
    "log_timestamp",
    "log_client_tag",
    "client_ip_header",
    "demand_eviction",
    // ADR 0048 rule 15.
    "peers",
    "replication_start",
    "replication_allow_private",
    "peer_ca_file",
    // ADR 0050 rule 28.
    "mirror_endpoint",
    "mirror_bucket",
    "mirror_region",
    "mirror_prefix",
    "mirror_url_style",
    "mirror_access_key_ref",
    "mirror_secret_key_ref",
    "mirror_session_token_ref",
    "mirror_info",
    "mirror_public_url",
    "mirror_allow_private",
    // ADR 0052 rule 21.
    "deny_file",
    // ADR 0054 rule 30.
    "ws_enabled",
];

/// `mirror_url_style` (ADR 0050 rule 28).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlStyle {
    /// `{endpoint}/{bucket}/{key}`, the default.
    Path,
    /// `{bucket}.{endpoint host}/{key}`.
    Virtual,
}

impl UrlStyle {
    /// The names, in the file and the environment.
    pub const NAMES: &'static [&'static str] = &["path", "virtual"];

    /// The name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Virtual => "virtual",
        }
    }

    /// Parses a name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "path" => Some(Self::Path),
            "virtual" => Some(Self::Virtual),
            _ => None,
        }
    }
}

/// An address block in CIDR notation (`192.0.2.0/24`, `2001:db8::/32`). Host bits must be zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    /// Network address.
    pub addr: IpAddr,
    /// Prefix length in bits.
    pub prefix: u8,
}

impl Cidr {
    /// Parses `s`. With `zero_prefix` false (`trusted_proxies`, ADR 0020 rule 13), a prefix of 0
    /// is refused, and the message for an IPv4-mapped block never suggests one.
    fn parse(s: &str, zero_prefix: bool) -> Result<Self, String> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| format!("`{s}` is not in CIDR notation (address/prefix)"))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{s}`: invalid IP address"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|p| *p <= max)
            .ok_or_else(|| format!("`{s}`: prefix must be 0 to {max}"))?;
        let cidr = Self { addr, prefix };
        if !cidr.contains(addr) || cidr.network() != addr {
            return Err(format!("`{s}`: host bits are set"));
        }
        // ADR 0020 rule 19: addresses are tested in their IPv4 form, so a mapped block never
        // matches. Nothing is converted (ADR 0018 rule 7).
        if let IpAddr::V6(v6) = addr
            && let Some(v4) = v6.to_ipv4_mapped()
            && prefix >= 96
        {
            let v4_prefix = prefix - 96;
            return Err(if v4_prefix == 0 && !zero_prefix {
                format!(
                    "`{s}` is an IPv4-mapped block, which never matches; its IPv4 form would \
                     trust every IPv4 address, which this setting refuses (ADR 0020 rule 13)"
                )
            } else {
                format!(
                    "`{s}` is an IPv4-mapped block, which never matches: write \
                     `{v4}/{v4_prefix}` instead"
                )
            });
        }
        // ADR 0020 rule 13: "trust every address" is never a proxy list.
        if prefix == 0 && !zero_prefix {
            return Err(format!(
                "`{s}` has a prefix of 0: every address could choose its client key \
                 (ADR 0020 rule 13)"
            ));
        }
        Ok(cidr)
    }

    /// Whether the block is wider than /16 (IPv4) or /32 (IPv6) (ADR 0020 rule 14).
    fn is_broad(self) -> bool {
        self.prefix < if self.addr.is_ipv4() { 16 } else { 32 }
    }

    /// Whether the two blocks share an address (same family, one contains the other).
    fn overlaps(self, other: Self) -> bool {
        self.contains(other.addr) || other.contains(self.addr)
    }

    pub(crate) fn network(self) -> IpAddr {
        match self.addr {
            IpAddr::V4(a) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V4((u32::from(a) & mask).into())
            }
            IpAddr::V6(a) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V6((u128::from(a) & mask).into())
            }
        }
    }

    /// Whether `ip` is in this block. An IPv4 block never contains an IPv6 address: callers
    /// normalise IPv4-mapped addresses first (`client::normalise`, ADR 0018 rule 20).
    #[must_use]
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                Self { addr: ip, ..self }.network() == self.network()
            }
            _ => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// `cors_allow_origins` (ADR 0012 rule 23).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorsOrigins {
    /// `*`: any origin (default).
    Any,
    /// An allow-list, compared byte for byte with `Origin`. May be empty.
    List(Vec<HeaderValue>),
}

impl fmt::Display for CorsOrigins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::List(l) => {
                let l: Vec<&str> = l.iter().map(|o| o.to_str().unwrap_or_default()).collect();
                f.write_str(&l.join(", "))
            }
        }
    }
}

/// Every relay setting, validated.
#[derive(Clone, Debug)]
#[allow(missing_docs)] // Each field is the setting of the same name, documented in its ADR.
#[allow(clippy::struct_excessive_bools)] // One field per setting.
pub struct Settings {
    // ADR 0019.
    pub profile: Profile,
    /// Default `127.0.0.1:8080`: public exposure goes through a reverse proxy (rule 9).
    pub listen: SocketAddr,
    /// Block store and index directory; default `data`, relative to the working directory.
    pub data_dir: PathBuf,
    pub max_connections_per_client: u64,
    pub max_connection_age_ms: u64,
    pub max_requests_per_connection: u64,
    // ADR 0007.
    pub min_pow_difficulty: u32,
    pub max_future_ms: u64,
    // ADR 0012.
    pub max_query_limit: u64,
    pub cors_allow_origins: CorsOrigins,
    // ADR 0013.
    /// `None` when the setting is 0: no eviction by age (ADR 0019 rule 6).
    pub block_ttl_ms: Option<u64>,
    pub max_store_bytes: u64,
    pub sweep_interval_ms: u64,
    pub sweep_batch: u64,
    pub index_cache_bytes: u64,
    // ADR 0018.
    pub worker_threads: u64,
    pub max_blocking_threads: u64,
    pub max_connections: u64,
    pub max_header_bytes: u64,
    pub header_timeout_ms: u64,
    pub body_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub index_max_readers: u64,
    pub index_max_queue: u64,
    pub block_max_readers: u64,
    pub block_max_queue: u64,
    pub put_max_in_flight: u64,
    pub put_max_queue: u64,
    pub put_max_in_flight_per_client: u64,
    pub queue_timeout_ms: u64,
    pub shed_retry_after_s: u64,
    pub rate_block_per_min: u64,
    pub rate_block_burst: u64,
    pub rate_query_per_min: u64,
    pub rate_query_burst: u64,
    pub rate_put_per_min: u64,
    pub rate_put_burst: u64,
    pub rate_limit_max_clients: u64,
    pub rate_limit_exempt: Vec<Cidr>,
    pub client_ipv6_prefix: u64,
    pub trusted_proxies: Vec<Cidr>,
    /// ADR 0044: the single-value header that holds the client address on a connection from a
    /// peer in `trusted_proxies`, lowercase; `None` (the default) reads `X-Forwarded-For`.
    pub client_ip_header: Option<String>,
    pub block_cache_bytes: u64,
    // ADR 0021.
    pub log_format: Format,
    pub log_level: Level,
    pub log_timestamp: Timestamp,
    pub log_client_tag: ClientTag,
    pub log_rate_per_min: u64,
    pub log_burst: u64,
    /// 0: no `stats` line.
    pub stats_interval_ms: u64,
    // ADR 0046 rule 24.
    /// Eviction by least recent demand under disk pressure; default `true`.
    pub demand_eviction: bool,
    pub demand_high_water_pct: u64,
    pub demand_low_water_pct: u64,
    /// The demand epoch `E`.
    pub demand_epoch_ms: u64,
    pub demand_touch_max: u64,
    // ADR 0048 rule 15.
    /// The peers to copy blocks from, normalised; empty (the default) turns replication off.
    pub peers: Vec<PeerUrl>,
    pub replication_start: ReplicationStart,
    /// Connect to loopback, private and link-local resolved addresses (rule 14); default `false`.
    pub replication_allow_private: bool,
    /// A PEM file of trust roots that replaces the operating system store (rule 19).
    pub peer_ca_file: Option<PathBuf>,
    pub replication_max_peers: u64,
    pub replication_max_in_flight: u64,
    pub replication_blocks_per_min: u64,
    pub replication_bytes_per_hour: u64,
    pub replication_poll_ms: u64,
    pub replication_request_timeout_ms: u64,
    pub replication_max_backoff_s: u64,
    pub replication_resync_margin_ms: u64,
    // ADR 0049 rule 14.
    /// `R`, the stored bytes per hour of the global cap; 0 turns ADR 0049 rules 2 to 7 off.
    pub ingest_bytes_per_hour: u64,
    pub ingest_group_max: u64,
    /// The share of `R` of an IPv6 /48 or an IPv4 /24, in percent.
    pub ingest_group_share_pct: u64,
    /// The share of `R` of an IPv6 /56, in percent.
    pub ingest_group56_share_pct: u64,
    // ADR 0050 rule 28.
    /// The S3 API URL; `None` (the default) turns the archive copy off.
    pub mirror_endpoint: Option<PeerUrl>,
    pub mirror_bucket: String,
    pub mirror_region: String,
    /// Empty, or ending with `/`.
    pub mirror_prefix: String,
    pub mirror_url_style: UrlStyle,
    /// Names of environment variables, never credentials (rule 22).
    pub mirror_access_key_ref: String,
    pub mirror_secret_key_ref: String,
    pub mirror_session_token_ref: Option<String>,
    /// Write the `/info` object of the read-only relay URL (rule 3).
    pub mirror_info: bool,
    /// The read-only relay URL that serves the bucket, for the check after a `412` (rule 9).
    pub mirror_public_url: Option<PeerUrl>,
    pub mirror_max_in_flight: u64,
    pub mirror_request_timeout_ms: u64,
    pub mirror_max_backoff_s: u64,
    pub mirror_allow_private: bool,
    // ADR 0052 rule 21.
    /// The operator deny list; `None` (the default) turns it off.
    pub deny_file: Option<PathBuf>,
    pub deny_max_entries: u64,
    pub deny_reload_ms: u64,
    // ADR 0054 rule 30.
    /// Serve `GET /sbtp/v1/subscribe`; default `false`.
    pub ws_enabled: bool,
    pub ws_max_connections: u64,
    pub ws_max_connections_per_client: u64,
    pub ws_max_subscriptions: u64,
    pub ws_group_share_pct: u64,
    pub ws_ping_interval_ms: u64,
    pub ws_max_age_ms: u64,
    /// The source of every setting (ADR 0019 rule 36.6).
    sources: BTreeMap<&'static str, Source>,
}

/// A start-up warning or note: the fields of the `config_warning` event (ADR 0021 rule 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// A fixed name.
    pub code: &'static str,
    /// The setting concerned.
    pub setting: &'static str,
    /// The text for a person.
    pub msg: String,
}

/// A configuration error. Each names the setting or the source at fault (rule 7).
#[derive(Debug)]
pub enum ConfigError {
    /// Command line not understood.
    Args(String),
    /// The configuration file could not be read or parsed.
    File(String),
    /// A key of the file, or an `SBTP_RELAY_*` variable, that names no setting.
    UnknownKey(String),
    /// A value of the wrong type or syntax.
    Invalid {
        /// Setting name.
        setting: &'static str,
        /// What was wrong.
        reason: String,
    },
    /// A value outside the range of the setting.
    OutOfRange {
        /// Setting name.
        setting: &'static str,
        /// The value given.
        value: String,
        /// Smallest valid value.
        min: u64,
        /// Largest valid value.
        max: u64,
    },
    /// A constraint between settings is broken (rule 22).
    Constraint(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Args(m) => write!(f, "command line: {m}"),
            Self::File(m) => write!(f, "configuration file: {m}"),
            Self::UnknownKey(k) => write!(f, "unknown setting `{k}`"),
            Self::Invalid { setting, reason } => write!(f, "setting `{setting}`: {reason}"),
            Self::OutOfRange {
                setting,
                value,
                min,
                max,
            } => write!(f, "setting `{setting}`: {value} is outside {min} to {max}"),
            Self::Constraint(m) => write!(f, "settings: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A value from one source, before typing.
enum Raw {
    Toml(toml::Value),
    Env(String),
}

impl Raw {
    fn source(&self) -> Source {
        match self {
            Self::Toml(_) => Source::File,
            Self::Env(_) => Source::Env,
        }
    }

    fn int(&self, setting: &'static str, min: u64, max: u64) -> Result<u64, ConfigError> {
        let range = |value: String| ConfigError::OutOfRange {
            setting,
            value,
            min,
            max,
        };
        let v = match self {
            Self::Toml(toml::Value::Integer(i)) => {
                u64::try_from(*i).map_err(|_| range(i.to_string()))?
            }
            Self::Env(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
                s.parse().map_err(|_| range(s.clone()))?
            }
            _ => {
                return Err(ConfigError::Invalid {
                    setting,
                    reason: "expected a non-negative integer".into(),
                });
            }
        };
        if (min..=max).contains(&v) {
            Ok(v)
        } else {
            Err(range(v.to_string()))
        }
    }

    fn string(&self, setting: &'static str) -> Result<String, ConfigError> {
        match self {
            Self::Toml(toml::Value::String(s)) | Self::Env(s) => Ok(s.clone()),
            Self::Toml(_) => Err(ConfigError::Invalid {
                setting,
                reason: "expected a string".into(),
            }),
        }
    }

    /// A list: a TOML array of strings, or a comma-separated string in the environment.
    fn list(&self, setting: &'static str) -> Result<Vec<String>, ConfigError> {
        let invalid = || ConfigError::Invalid {
            setting,
            reason: "expected an array of strings".into(),
        };
        match self {
            Self::Env(s) if s.trim().is_empty() => Ok(Vec::new()),
            Self::Env(s) => Ok(s.split(',').map(|i| i.trim().to_owned()).collect()),
            Self::Toml(toml::Value::Array(a)) => a
                .iter()
                .map(|v| v.as_str().map(str::to_owned).ok_or_else(invalid))
                .collect(),
            Self::Toml(_) => Err(invalid()),
        }
    }
}

impl Settings {
    /// Loads the settings from `args` (the command line without the program name) and `env` (the
    /// process environment, or a test's), reading the file named by `--config` or
    /// `SBTP_RELAY_CONFIG`, then validates them.
    ///
    /// # Errors
    ///
    /// Any [`ConfigError`]; the relay must not start.
    pub fn load<A, E>(args: A, env: E) -> Result<Self, ConfigError>
    where
        A: IntoIterator<Item = OsString>,
        E: IntoIterator<Item = (OsString, OsString)>,
    {
        let mut values: BTreeMap<String, Raw> = BTreeMap::new();
        let mut env_values = Vec::new();
        let mut env_config = None;
        for (k, v) in env {
            let Some(k) = k.to_str() else { continue };
            if !k.starts_with(ENV_PREFIX) {
                continue;
            }
            let v = v
                .into_string()
                .map_err(|_| ConfigError::Args(format!("{k} is not valid UTF-8")))?;
            if k == ENV_CONFIG {
                env_config = Some(PathBuf::from(v));
            } else {
                env_values.push((k.to_owned(), v));
            }
        }
        let path = match parse_args(args)? {
            Some(p) => Some(p),
            None => env_config,
        };
        if let Some(path) = path {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| ConfigError::File(format!("{}: {e}", path.display())))?;
            let table: toml::Table = text
                .parse()
                .map_err(|e: toml::de::Error| ConfigError::File(e.to_string()))?;
            for (k, v) in table {
                values.insert(k, Raw::Toml(v));
            }
        }
        for (k, v) in env_values {
            let name = k.get(ENV_PREFIX.len()..).unwrap_or_default();
            if name.is_empty() || name.bytes().any(|b| b.is_ascii_lowercase()) {
                return Err(ConfigError::UnknownKey(k));
            }
            let name = name.to_ascii_lowercase();
            if !is_known(&name) {
                return Err(ConfigError::UnknownKey(k));
            }
            values.insert(name, Raw::Env(v));
        }
        Self::finish(values)
    }

    #[allow(clippy::too_many_lines)] // One field per setting.
    fn finish(mut values: BTreeMap<String, Raw>) -> Result<Self, ConfigError> {
        let source = |r: &Option<Raw>| r.as_ref().map_or(Source::Default, Raw::source);
        // Rule 36.1: the profile first.
        let raw = values.remove("profile");
        let profile_source = source(&raw);
        let profile = parse_profile(raw)?;
        let (mut ints, mut sources) = resolve_ints(&mut values, profile)?;
        sources.insert("profile", profile_source);
        // Rule 36.3: computed defaults last, from the effective values.
        let cpus = std::thread::available_parallelism()
            .map_or(1, |n| u64::try_from(n.get()).unwrap_or(256))
            .clamp(1, 256);
        let worker_threads = *ints.worker_threads.get_or_insert(cpus);
        let v = |o: Option<u64>| o.unwrap_or_default(); // Every slot holds a value here.

        let mut other = |key: &'static str| {
            let raw = values.remove(key);
            sources.insert(key, source(&raw));
            raw
        };
        let listen = parse_listen(other("listen"))?;
        let data_dir = parse_data_dir(other("data_dir"))?;
        let cors_allow_origins = parse_cors(other("cors_allow_origins"))?;
        // ADR 0020 rule 15: a prefix of 0 is accepted for exemption (with a warning).
        let rate_limit_exempt =
            parse_cidrs(other("rate_limit_exempt"), "rate_limit_exempt", &[], true)?;
        // ADR 0020 rule 13: refused for trust.
        let trusted_proxies = parse_cidrs(
            other("trusted_proxies"),
            "trusted_proxies",
            &["127.0.0.1/32", "::1/128"],
            false,
        )?;
        let client_ip_header = parse_client_ip_header(other("client_ip_header"))?;
        let demand_eviction = parse_bool(other("demand_eviction"), "demand_eviction")?;
        let ws_enabled = parse_bool(other("ws_enabled"), "ws_enabled")?;
        let peers = parse_peers(other("peers"))?;
        let mirror_endpoint = parse_url(other("mirror_endpoint"), "mirror_endpoint")?;
        let max_blocking_threads = *ints.max_blocking_threads.get_or_insert(blocking_floor(
            v(ints.block_max_readers),
            v(ints.put_max_in_flight),
            !peers.is_empty() && cfg!(feature = "replication"),
            v(ints.replication_max_in_flight),
            if mirror_endpoint.is_some() && cfg!(feature = "object-store") {
                v(ints.mirror_max_in_flight)
            } else {
                0
            },
        ));
        let mirror_bucket = parse_text(other("mirror_bucket"), "mirror_bucket", "", valid_bucket)?;
        let mirror_region = parse_text(
            other("mirror_region"),
            "mirror_region",
            "us-east-1",
            valid_region,
        )?;
        let mirror_prefix = parse_text(other("mirror_prefix"), "mirror_prefix", "", valid_prefix)?;
        let mirror_url_style = parse_choice(
            other("mirror_url_style"),
            "mirror_url_style",
            UrlStyle::parse,
            UrlStyle::NAMES,
        )?;
        let mirror_access_key_ref =
            parse_var_name(other("mirror_access_key_ref"), "mirror_access_key_ref")?
                .unwrap_or_else(|| "SBTP_MIRROR_ACCESS_KEY_ID".to_owned());
        let mirror_secret_key_ref =
            parse_var_name(other("mirror_secret_key_ref"), "mirror_secret_key_ref")?
                .unwrap_or_else(|| "SBTP_MIRROR_SECRET_ACCESS_KEY".to_owned());
        let mirror_session_token_ref = parse_var_name(
            other("mirror_session_token_ref"),
            "mirror_session_token_ref",
        )?;
        let mirror_info = parse_bool(other("mirror_info"), "mirror_info")?;
        let mirror_public_url = parse_url(other("mirror_public_url"), "mirror_public_url")?;
        let mirror_allow_private =
            parse_bool(other("mirror_allow_private"), "mirror_allow_private")?;
        let replication_allow_private = parse_bool(
            other("replication_allow_private"),
            "replication_allow_private",
        )?;
        // ADR 0052 rule 21: empty is off, as the default.
        let deny_file = other("deny_file")
            .map(|r| r.string("deny_file"))
            .transpose()?
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let peer_ca_file = other("peer_ca_file")
            .map(|r| parse_path(&r, "peer_ca_file"))
            .transpose()?;
        let replication_start = parse_choice(
            other("replication_start"),
            "replication_start",
            ReplicationStart::parse,
            ReplicationStart::NAMES,
        )?;
        // Strings of one fixed set each (ADR 0021 rule 46), parsed by the `choice!` of `log`.
        macro_rules! choice {
            ($t:ident, $k:literal) => {
                parse_choice(other($k), $k, $t::parse, $t::NAMES)?
            };
        }
        let log_format = choice!(Format, "log_format");
        let log_level = choice!(Level, "log_level");
        let log_timestamp = choice!(Timestamp, "log_timestamp");
        let log_client_tag = choice!(ClientTag, "log_client_tag");

        let s = Self {
            profile,
            listen,
            data_dir,
            max_connections_per_client: v(ints.max_connections_per_client),
            max_connection_age_ms: v(ints.max_connection_age_ms),
            max_requests_per_connection: v(ints.max_requests_per_connection),
            // In range 0 to 256.
            min_pow_difficulty: u32::try_from(v(ints.min_pow_difficulty)).unwrap_or(u32::MAX),
            max_future_ms: v(ints.max_future_ms),
            max_query_limit: v(ints.max_query_limit),
            cors_allow_origins,
            block_ttl_ms: ints.block_ttl_ms.filter(|t| *t != 0),
            max_store_bytes: v(ints.max_store_bytes),
            sweep_interval_ms: v(ints.sweep_interval_ms),
            sweep_batch: v(ints.sweep_batch),
            index_cache_bytes: v(ints.index_cache_bytes),
            worker_threads,
            max_blocking_threads,
            max_connections: v(ints.max_connections),
            max_header_bytes: v(ints.max_header_bytes),
            header_timeout_ms: v(ints.header_timeout_ms),
            body_timeout_ms: v(ints.body_timeout_ms),
            request_timeout_ms: v(ints.request_timeout_ms),
            idle_timeout_ms: v(ints.idle_timeout_ms),
            index_max_readers: v(ints.index_max_readers),
            index_max_queue: v(ints.index_max_queue),
            block_max_readers: v(ints.block_max_readers),
            block_max_queue: v(ints.block_max_queue),
            put_max_in_flight: v(ints.put_max_in_flight),
            put_max_queue: v(ints.put_max_queue),
            put_max_in_flight_per_client: v(ints.put_max_in_flight_per_client),
            queue_timeout_ms: v(ints.queue_timeout_ms),
            shed_retry_after_s: v(ints.shed_retry_after_s),
            rate_block_per_min: v(ints.rate_block_per_min),
            rate_block_burst: v(ints.rate_block_burst),
            rate_query_per_min: v(ints.rate_query_per_min),
            rate_query_burst: v(ints.rate_query_burst),
            rate_put_per_min: v(ints.rate_put_per_min),
            rate_put_burst: v(ints.rate_put_burst),
            rate_limit_max_clients: v(ints.rate_limit_max_clients),
            rate_limit_exempt,
            client_ipv6_prefix: v(ints.client_ipv6_prefix),
            trusted_proxies,
            client_ip_header,
            block_cache_bytes: v(ints.block_cache_bytes),
            log_format: log_format.unwrap_or(Format::Text),
            log_level: log_level.unwrap_or(Level::Info),
            log_timestamp: log_timestamp.unwrap_or(Timestamp::Rfc3339),
            log_client_tag: log_client_tag.unwrap_or(ClientTag::Off),
            log_rate_per_min: v(ints.log_rate_per_min),
            log_burst: v(ints.log_burst),
            stats_interval_ms: v(ints.stats_interval_ms),
            demand_eviction: demand_eviction.unwrap_or(true),
            demand_high_water_pct: v(ints.demand_high_water_pct),
            demand_low_water_pct: v(ints.demand_low_water_pct),
            demand_epoch_ms: v(ints.demand_epoch_ms),
            demand_touch_max: v(ints.demand_touch_max),
            peers,
            replication_start: replication_start.unwrap_or(ReplicationStart::Now),
            replication_allow_private: replication_allow_private.unwrap_or(false),
            peer_ca_file,
            replication_max_peers: v(ints.replication_max_peers),
            replication_max_in_flight: v(ints.replication_max_in_flight),
            replication_blocks_per_min: v(ints.replication_blocks_per_min),
            replication_bytes_per_hour: v(ints.replication_bytes_per_hour),
            replication_poll_ms: v(ints.replication_poll_ms),
            replication_request_timeout_ms: v(ints.replication_request_timeout_ms),
            replication_max_backoff_s: v(ints.replication_max_backoff_s),
            replication_resync_margin_ms: v(ints.replication_resync_margin_ms),
            ingest_bytes_per_hour: v(ints.ingest_bytes_per_hour),
            ingest_group_max: v(ints.ingest_group_max),
            ingest_group_share_pct: v(ints.ingest_group_share_pct),
            ingest_group56_share_pct: v(ints.ingest_group56_share_pct),
            mirror_endpoint,
            mirror_bucket,
            mirror_region,
            mirror_prefix,
            mirror_url_style: mirror_url_style.unwrap_or(UrlStyle::Path),
            mirror_access_key_ref,
            mirror_secret_key_ref,
            mirror_session_token_ref,
            mirror_info: mirror_info.unwrap_or(true),
            mirror_public_url,
            mirror_max_in_flight: v(ints.mirror_max_in_flight),
            mirror_request_timeout_ms: v(ints.mirror_request_timeout_ms),
            mirror_max_backoff_s: v(ints.mirror_max_backoff_s),
            mirror_allow_private: mirror_allow_private.unwrap_or(false),
            deny_file,
            deny_max_entries: v(ints.deny_max_entries),
            deny_reload_ms: v(ints.deny_reload_ms),
            ws_enabled: ws_enabled.unwrap_or(false),
            ws_max_connections: v(ints.ws_max_connections),
            ws_max_connections_per_client: v(ints.ws_max_connections_per_client),
            ws_max_subscriptions: v(ints.ws_max_subscriptions),
            ws_group_share_pct: v(ints.ws_group_share_pct),
            ws_ping_interval_ms: v(ints.ws_ping_interval_ms),
            ws_max_age_ms: v(ints.ws_max_age_ms),
            sources,
        };
        s.check_constraints()?;
        Ok(s)
    }

    /// The source of the effective value of `setting` (ADR 0019 rule 36.6).
    #[must_use]
    pub fn source(&self, setting: &str) -> Option<Source> {
        self.sources.get(setting).copied()
    }

    /// The effective value of `setting` as logged, from the typed field. `block_ttl_ms` is 0 when
    /// eviction by age is disabled, as it is written in the file.
    #[allow(clippy::too_many_lines)] // One arm per setting.
    fn value_text(&self, setting: &str) -> Option<String> {
        let cidrs = |l: &[Cidr]| l.iter().map(Cidr::to_string).collect::<Vec<_>>().join(", ");
        macro_rules! ints {
            ($($f:ident),*) => {
                match setting {
                    $(stringify!($f) => Some(self.$f.to_string()),)*
                    "block_ttl_ms" => Some(self.block_ttl_ms.unwrap_or(0).to_string()),
                    "profile" => Some(self.profile.name().to_owned()),
                    "listen" => Some(self.listen.to_string()),
                    "data_dir" => Some(self.data_dir.display().to_string()),
                    "cors_allow_origins" => Some(self.cors_allow_origins.to_string()),
                    "rate_limit_exempt" => Some(cidrs(&self.rate_limit_exempt)),
                    "trusted_proxies" => Some(cidrs(&self.trusted_proxies)),
                    "log_format" => Some(self.log_format.name().to_owned()),
                    "log_level" => Some(self.log_level.name().to_owned()),
                    "log_timestamp" => Some(self.log_timestamp.name().to_owned()),
                    "log_client_tag" => Some(self.log_client_tag.name().to_owned()),
                    "client_ip_header" => Some(self.client_ip_header.clone().unwrap_or_default()),
                    "demand_eviction" => Some(self.demand_eviction.to_string()),
                    // ADR 0048: the number of peers only; logs name a peer by its position.
                    "peers" => Some(self.peers.len().to_string()),
                    "replication_start" => Some(self.replication_start.name().to_owned()),
                    "replication_allow_private" => {
                        Some(self.replication_allow_private.to_string())
                    }
                    "peer_ca_file" => Some(
                        self.peer_ca_file
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                    ),
                    // ADR 0050: whether the endpoint is set, not its URL (an account name may be
                    // part of its host). No other mirror setting holds a secret (rule 22).
                    "mirror_endpoint" => Some(
                        if self.mirror_endpoint.is_some() { "set" } else { "" }.to_owned(),
                    ),
                    "mirror_bucket" => Some(self.mirror_bucket.clone()),
                    "mirror_region" => Some(self.mirror_region.clone()),
                    "mirror_prefix" => Some(self.mirror_prefix.clone()),
                    "mirror_url_style" => Some(self.mirror_url_style.name().to_owned()),
                    // Deny review I-7: a `*_ref` is logged only when the archive copy is
                    // configured, which checks that it names a variable that is set; otherwise
                    // a value pasted by mistake would reach the log.
                    "mirror_access_key_ref" | "mirror_secret_key_ref"
                    | "mirror_session_token_ref"
                        if self.mirror_endpoint.is_none() =>
                    {
                        Some("unused".to_owned())
                    }
                    "mirror_access_key_ref" => Some(self.mirror_access_key_ref.clone()),
                    "mirror_secret_key_ref" => Some(self.mirror_secret_key_ref.clone()),
                    "mirror_session_token_ref" => {
                        Some(self.mirror_session_token_ref.clone().unwrap_or_default())
                    }
                    "mirror_info" => Some(self.mirror_info.to_string()),
                    "mirror_public_url" => Some(
                        self.mirror_public_url
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_default(),
                    ),
                    "mirror_allow_private" => Some(self.mirror_allow_private.to_string()),
                    "ws_enabled" => Some(self.ws_enabled.to_string()),
                    // ADR 0052 rule 20: the path, never the content of the file.
                    "deny_file" => Some(
                        self.deny_file
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                    ),
                    _ => None,
                }
            };
        }
        ints!(
            min_pow_difficulty,
            max_future_ms,
            max_query_limit,
            max_store_bytes,
            sweep_interval_ms,
            sweep_batch,
            index_cache_bytes,
            worker_threads,
            max_blocking_threads,
            max_connections,
            max_connections_per_client,
            max_connection_age_ms,
            max_requests_per_connection,
            max_header_bytes,
            header_timeout_ms,
            body_timeout_ms,
            request_timeout_ms,
            idle_timeout_ms,
            index_max_readers,
            index_max_queue,
            block_max_readers,
            block_max_queue,
            put_max_in_flight,
            put_max_queue,
            put_max_in_flight_per_client,
            queue_timeout_ms,
            shed_retry_after_s,
            rate_block_per_min,
            rate_block_burst,
            rate_query_per_min,
            rate_query_burst,
            rate_put_per_min,
            rate_put_burst,
            rate_limit_max_clients,
            client_ipv6_prefix,
            block_cache_bytes,
            log_rate_per_min,
            log_burst,
            stats_interval_ms,
            demand_high_water_pct,
            demand_low_water_pct,
            demand_epoch_ms,
            deny_max_entries,
            deny_reload_ms,
            demand_touch_max,
            replication_max_peers,
            replication_max_in_flight,
            replication_blocks_per_min,
            replication_bytes_per_hour,
            replication_poll_ms,
            replication_request_timeout_ms,
            replication_max_backoff_s,
            replication_resync_margin_ms,
            ingest_bytes_per_hour,
            ingest_group_max,
            ingest_group_share_pct,
            ingest_group56_share_pct,
            mirror_max_in_flight,
            mirror_request_timeout_ms,
            mirror_max_backoff_s,
            ws_max_connections,
            ws_max_connections_per_client,
            ws_max_subscriptions,
            ws_group_share_pct,
            ws_ping_interval_ms,
            ws_max_age_ms
        )
    }

    /// The warnings of the start-up log (ADR 0019 rules 2, 9 and 38; ADR 0018 rule 17; ADR 0020
    /// rules 14 to 18; ADR 0021 rules 13 and 14), each with its fixed code (`config_warning`).
    #[must_use]
    #[allow(clippy::too_many_lines)] // A flat list, one block per warning.
    pub fn config_warnings(&self) -> Vec<Warning> {
        let mut w = Vec::new();
        let mut add = |code, setting, msg: String| w.push(Warning { code, setting, msg });
        // ADR 0045 rule 3.
        if self.min_pow_difficulty > sbtp_core::NETWORK_POW_DIFFICULTY {
            add(
                "pow_above_network",
                "min_pow_difficulty",
                format!(
                    "min_pow_difficulty = {} is above the network difficulty {}: this relay is \
                     outside the network difficulty; blocks accepted by other relays may be \
                     refused (ADR 0045 rule 3)",
                    self.min_pow_difficulty,
                    sbtp_core::NETWORK_POW_DIFFICULTY
                ),
            );
        }
        if self.min_pow_difficulty == 0 {
            add(
                "no_pow",
                "min_pow_difficulty",
                "min_pow_difficulty = 0: blocks are accepted without proof of work".into(),
            );
        }
        if !self.listen.ip().is_loopback() {
            add(
                "listen_not_loopback",
                "listen",
                format!(
                    "listen = {} is not a loopback address: the relay serves plain HTTP on it; a \
                 public relay belongs behind a reverse proxy (ADR 0019 rule 42)",
                    self.listen
                ),
            );
        }
        if self.profile != Profile::Small && self.source("max_store_bytes") == Some(Source::Default)
        {
            add(
                "profile_store_default",
                "max_store_bytes",
                format!(
                    "profile {} with max_store_bytes at its default ({} bytes): a profile does not \
                 set the disk quota (ADR 0019 rule 38)",
                    self.profile.name(),
                    self.max_store_bytes
                ),
            );
        }
        if self.index_max_readers > DEFAULT_INDEX_MAX_READERS {
            add(
                "index_readers_unmeasured",
                "index_max_readers",
                format!(
                    "index_max_readers = {} exceeds the default of this target ({}), which is the \
                 only value measured as bounded (ADR 0018 rule 17)",
                    self.index_max_readers, DEFAULT_INDEX_MAX_READERS
                ),
            );
        }
        // ADR 0020 rule 14.
        for c in self.trusted_proxies.iter().filter(|c| c.is_broad()) {
            add(
                "trusted_proxies_broad",
                "trusted_proxies",
                format!(
                    "trusted_proxies block {c} is wider than /16 (IPv4) or /32 (IPv6): every address \
                 in it may write X-Forwarded-For and is not counted at accept (ADR 0020 rule 14)"
                ),
            );
        }
        // ADR 0020 rule 15.
        for c in self.rate_limit_exempt.iter().filter(|c| c.is_broad()) {
            add(
                "exempt_broad",
                "rate_limit_exempt",
                format!(
                    "rate_limit_exempt block {c} is wider than /16 (IPv4) or /32 (IPv6): the \
                 per-client rules do not apply to any address in it (ADR 0020 rule 15)"
                ),
            );
        }
        for t in &self.trusted_proxies {
            for e in self.rate_limit_exempt.iter().filter(|e| e.overlaps(*t)) {
                add(
                    "trusted_exempt_overlap",
                    "trusted_proxies",
                    format!(
                        "trusted_proxies block {t} and rate_limit_exempt block {e} share addresses: \
                     a request without a client address in X-Forwarded-For is exempt \
                     (ADR 0020 rule 15)"
                    ),
                );
            }
        }
        // ADR 0020 rule 18 (security review L-6).
        if self.max_connections_per_client.saturating_mul(2) > self.max_connections {
            add(
                "per_client_over_half",
                "max_connections_per_client",
                format!(
                    "max_connections_per_client = {} ({}) is more than half of max_connections = {} \
                 ({}): one client key may hold most connection slots (ADR 0020 rule 18)",
                    self.max_connections_per_client,
                    self.source("max_connections_per_client")
                        .unwrap_or(Source::Default),
                    self.max_connections,
                    self.source("max_connections").unwrap_or(Source::Default),
                ),
            );
        }
        // ADR 0021 rules 13 and 14.
        if self.log_level == Level::Debug {
            add(
                "debug_level",
                "log_level",
                "log_level = debug: the log holds one line per request and block_id suffixes \
                 (ADR 0021 rule 14)"
                    .into(),
            );
        }
        if self.log_client_tag == ClientTag::Keyed {
            add(
                "client_tag_keyed",
                "log_client_tag",
                "log_client_tag = keyed: lines about one client carry a pseudonymous tag, \
                 linkable within this process run (ADR 0021 rule 13)"
                    .into(),
            );
        }
        // ADR 0048 rule 14.
        if self.replication_allow_private && !self.peers.is_empty() {
            add(
                "replication_private",
                "replication_allow_private",
                "replication_allow_private = true: peer names may resolve to loopback, private \
                 and link-local addresses, cloud metadata included (ADR 0048 rule 14)"
                    .into(),
            );
        }
        // ADR 0050 rule 23.
        if self.mirror_allow_private && self.mirror_endpoint.is_some() {
            add(
                "mirror_private",
                "mirror_allow_private",
                "mirror_allow_private = true: the endpoint and public URL names may resolve to \
                 loopback, private and link-local addresses, cloud metadata included \
                 (ADR 0050 rule 23)"
                    .into(),
            );
        }
        w
    }

    /// Start-up lines that are not warnings (ADR 0020 rule 16). The log has no note event: they
    /// are written as `config_warning` lines with their own code.
    #[must_use]
    pub fn config_notes(&self) -> Vec<Warning> {
        let loopback = |c: &Cidr| {
            c.addr.is_loopback()
                || c.contains(IpAddr::V4(Ipv4Addr::LOCALHOST))
                || c.contains(IpAddr::V6(Ipv6Addr::LOCALHOST))
        };
        let mut n = Vec::new();
        if self.trusted_proxies.iter().any(loopback) {
            n.push(Warning {
                code: "trusted_loopback",
                setting: "trusted_proxies",
                msg: "trusted_proxies contains a loopback address: every local process is trusted to \
                 write X-Forwarded-For; a forwarder on this host that does not write it needs \
                 trusted_proxies = [] (ADR 0020 rules 16 and 17)"
                    .to_owned(),
            });
        }
        // ADR 0044 rule 7: the trust the setting implies, once at start-up.
        if let Some(h) = &self.client_ip_header {
            n.push(Warning {
                code: "client_ip_header",
                setting: "client_ip_header",
                msg: format!(
                    "the client address is read from the {h} header on connections from \
                     trusted_proxies, which are trusted to forward it unchanged from the CDN; \
                     X-Forwarded-For is not read (ADR 0044)"
                ),
            });
        }
        n
    }

    /// ADR 0018 rule 22 and ADR 0019 rules 5 and 28, on the effective values. The open-file limit
    /// is checked by [`Settings::check_open_files`].
    #[allow(clippy::too_many_lines)] // A flat list, one block per constraint.
    fn check_constraints(&self) -> Result<(), ConfigError> {
        for (setting, bytes) in [
            ("index_cache_bytes", self.index_cache_bytes),
            ("block_cache_bytes", self.block_cache_bytes),
        ] {
            if usize::try_from(bytes).is_err() {
                return Err(ConfigError::Invalid {
                    setting,
                    reason: "not representable as a memory size on this target".into(),
                });
            }
        }
        let c = |ok: bool, m: &str| {
            if ok {
                Ok(())
            } else {
                Err(ConfigError::Constraint(m.to_owned()))
            }
        };
        // ADR 0054 rule 30, checked only with `ws_enabled`: a relay with the function off and
        // `max_connections = 1` keeps starting.
        if self.ws_enabled {
            c(
                self.ws_max_connections <= self.max_connections / 2,
                "ws_max_connections must not exceed half of max_connections",
            )?;
            c(
                self.ws_max_connections_per_client <= self.ws_max_connections,
                "ws_max_connections_per_client must not exceed ws_max_connections",
            )?;
        }
        c(
            self.queue_timeout_ms < self.request_timeout_ms,
            "queue_timeout_ms must be less than request_timeout_ms",
        )?;
        c(
            self.header_timeout_ms <= self.request_timeout_ms,
            "header_timeout_ms must not exceed request_timeout_ms",
        )?;
        c(
            self.body_timeout_ms <= self.request_timeout_ms,
            "body_timeout_ms must not exceed request_timeout_ms",
        )?;
        c(
            self.put_max_in_flight_per_client <= self.put_max_in_flight,
            "put_max_in_flight_per_client must not exceed put_max_in_flight",
        )?;
        c(
            self.max_connections_per_client <= self.max_connections,
            "max_connections_per_client must not exceed max_connections",
        )?;
        // ADR 0046 rule 24: checked whether or not `demand_eviction` is on.
        if self.demand_low_water_pct >= self.demand_high_water_pct {
            return Err(ConfigError::Constraint(format!(
                "demand_low_water_pct ({}) must be less than demand_high_water_pct ({})",
                self.demand_low_water_pct, self.demand_high_water_pct
            )));
        }
        // ADR 0049 rule 14.
        if self.ingest_bytes_per_hour != 0 && self.ingest_bytes_per_hour < MIN_INGEST_BYTES_PER_HOUR
        {
            return Err(ConfigError::Constraint(format!(
                "ingest_bytes_per_hour ({}) must be 0 (off) or at least {MIN_INGEST_BYTES_PER_HOUR}",
                self.ingest_bytes_per_hour
            )));
        }
        // ADR 0051 rule 21 (security review 2026-11-21, L-1).
        for (name, value, min, what) in [
            (
                "rate_block_burst",
                self.rate_block_burst,
                MIN_BLOCK_BURST,
                "a batch of 256 identifiers",
            ),
            (
                "rate_query_burst",
                self.rate_query_burst,
                MIN_QUERY_BURST,
                "a grouped query of 32 parents",
            ),
        ] {
            if value < min {
                return Err(ConfigError::Constraint(format!(
                    "{name} ({value}) must be at least {min}, the weight of {what} (ADR 0051 \
                     rule 21): a smaller burst would cap that weight and serve more per token"
                )));
            }
        }
        if self.ingest_group56_share_pct > self.ingest_group_share_pct {
            return Err(ConfigError::Constraint(format!(
                "ingest_group56_share_pct ({}) must not exceed ingest_group_share_pct ({})",
                self.ingest_group56_share_pct, self.ingest_group_share_pct
            )));
        }
        // ADR 0018 clarification M5 (ADR 0027 rule 4): at most `max_connections` keys are pinned,
        // so at least half of the limiter table can always be dropped once full. The message
        // names both settings and their effective values.
        if self.rate_limit_max_clients < self.max_connections.saturating_mul(2) {
            return Err(ConfigError::Constraint(format!(
                "rate_limit_max_clients ({}) must be at least 2 x max_connections ({} x 2 = {})",
                self.rate_limit_max_clients,
                self.max_connections,
                self.max_connections.saturating_mul(2)
            )));
        }
        self.check_replication()?;
        self.check_mirror()?;
        // Also checked when `max_blocking_threads` is left at its derived default, which can
        // exceed 512 (range "that sum to 512").
        let floor = blocking_floor(
            self.block_max_readers,
            self.put_max_in_flight,
            self.replication_on(),
            self.replication_max_in_flight,
            if self.mirror_on() {
                self.mirror_max_in_flight
            } else {
                0
            },
        );
        c(
            (floor..=512).contains(&self.max_blocking_threads),
            "max_blocking_threads must be from block_max_readers + put_max_in_flight + 2 (plus \
             replication_max_in_flight + 1 when peers is set, plus mirror_max_in_flight + 1 \
             when mirror_endpoint is set) to 512",
        )
    }

    /// ADR 0050 rules 22 and 28.
    fn check_mirror(&self) -> Result<(), ConfigError> {
        // Rule 28 (ADR 0048 rule 3, item 1): without the feature, every `mirror_*` setting keeps
        // its default.
        if !cfg!(feature = "object-store") {
            let given: Vec<&'static str> = self
                .sources
                .iter()
                .filter(|(n, src)| {
                    n.starts_with("mirror_") && matches!(src, Source::File | Source::Env)
                })
                .map(|(n, _)| *n)
                .collect();
            if given.is_empty() {
                return Ok(());
            }
            // The defaults of this profile; no `mirror_*` setting is given there, so this
            // check returns above for them.
            let defaults = Self::finish(BTreeMap::from([(
                "profile".to_owned(),
                Raw::Env(self.profile.name().to_owned()),
            )]))?;
            for name in given {
                if self.value_text(name) != defaults.value_text(name) {
                    return Err(ConfigError::Invalid {
                        setting: name,
                        reason: "this build has no `object-store` feature; leave the mirror_* \
                                 settings at their defaults"
                            .into(),
                    });
                }
            }
            return Ok(());
        }
        if self.mirror_endpoint.is_some() && self.mirror_bucket.is_empty() {
            return Err(ConfigError::Constraint(
                "mirror_endpoint is set without mirror_bucket (ADR 0050 rule 28)".into(),
            ));
        }
        Ok(())
    }

    /// Whether the archive copy runs: compiled in and `mirror_endpoint` set (ADR 0050 rule 26).
    #[must_use]
    pub fn mirror_on(&self) -> bool {
        cfg!(feature = "object-store") && self.mirror_endpoint.is_some()
    }

    /// ADR 0048 rules 2, 3 and 15.
    fn check_replication(&self) -> Result<(), ConfigError> {
        if self.peers.is_empty() {
            return Ok(());
        }
        // Rule 3, item 1: a setting that needs a feature absent from the build stops the start-up.
        if !cfg!(feature = "replication") {
            return Err(ConfigError::Invalid {
                setting: "peers",
                reason: "this build has no `replication` feature; leave peers empty".into(),
            });
        }
        if u64::try_from(self.peers.len()).unwrap_or(u64::MAX) > self.replication_max_peers {
            return Err(ConfigError::Constraint(format!(
                "peers has {} entries, more than replication_max_peers ({})",
                self.peers.len(),
                self.replication_max_peers
            )));
        }
        // Rule 2, ADR 0045 rule 3.
        if self.min_pow_difficulty > sbtp_core::NETWORK_POW_DIFFICULTY {
            return Err(ConfigError::Constraint(format!(
                "a relay that replicates (peers not empty) must not set min_pow_difficulty ({}) \
                 above the network difficulty {} (ADR 0048 rule 2)",
                self.min_pow_difficulty,
                sbtp_core::NETWORK_POW_DIFFICULTY
            )));
        }
        Ok(())
    }

    /// Whether replication runs: compiled in and `peers` not empty (ADR 0048 rule 3).
    #[must_use]
    pub fn replication_on(&self) -> bool {
        cfg!(feature = "replication") && !self.peers.is_empty()
    }

    /// The open-file limit the process needs (ADR 0018 rule 22).
    #[must_use]
    pub fn open_files_needed(&self) -> u64 {
        self.max_connections + self.block_max_readers + self.put_max_in_flight + 32
    }

    /// Checks the soft open-file limit of the process against [`Settings::open_files_needed`]
    /// (ADR 0019 rule 22) and returns it (`u64::MAX` for `unlimited`). Returns `Ok(None)` where
    /// the limit cannot be read without `unsafe` or a new dependency (targets other than Linux):
    /// the caller logs that it was not checked and the number needed.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Constraint`] when the limit is too low.
    pub fn check_open_files(&self) -> Result<Option<u64>, ConfigError> {
        let Some(limit) = soft_open_file_limit() else {
            return Ok(None);
        };
        if limit < self.open_files_needed() {
            return Err(ConfigError::Constraint(format!(
                "the open-file limit ({limit}) is below max_connections + block_max_readers + \
                 put_max_in_flight + 32 ({})",
                self.open_files_needed()
            )));
        }
        Ok(Some(limit))
    }

    /// The memory bound of ADR 0018 rule 35, from its estimates, in bytes.
    #[must_use]
    pub fn memory_bound_bytes(&self) -> u64 {
        let max_block = u64::try_from(sbtp_core::layout::MAX_BLOCK_LEN).unwrap_or(u64::MAX);
        [
            EST_BASELINE,
            self.index_cache_bytes,
            self.block_cache_bytes,
            self.max_connections
                .saturating_mul(self.max_header_bytes + EST_LARGEST_RESPONSE),
            self.put_max_in_flight.saturating_mul(max_block),
            (self.index_max_readers + self.block_max_readers).saturating_mul(EST_READ_WORKING_SET),
            self.rate_limit_max_clients
                .saturating_mul(EST_LIMITER_ENTRY),
            // ADR 0019 rule 31: two per-client tables (connections, requests in flight), each of
            // at most `max_connections` keys, and the pins of the limiter (ADR 0027 rule 4), the
            // same shape, at most `max_connections` keys, counted twice (conservative).
            self.max_connections
                .saturating_mul(4 * EST_CLIENT_COUNT_ENTRY),
            // ADR 0021 rule 45.
            LOG_QUEUE_BYTES,
            // ADR 0046 rule 25: the demand set, allocated once at start-up, and one flush chunk.
            if self.demand_eviction {
                crate::demand::memory_bytes(self.demand_touch_max)
            } else {
                0
            },
            // ADR 0048 rule 16: only when replication runs.
            if self.replication_on() {
                crate::peers::memory_bytes(
                    self.replication_max_in_flight,
                    self.replication_max_peers,
                )
            } else {
                0
            },
            // ADR 0050 rule 27: per upload in flight, a block and the TLS and HTTP state; the
            // uploader's window; the root store, unless replication already counts it.
            if self.mirror_on() {
                self.mirror_max_in_flight
                    .saturating_mul(EST_MIRROR_PER_REQUEST)
                    .saturating_add(EST_MIRROR_WINDOW)
                    .saturating_add(if self.replication_on() {
                        0
                    } else {
                        crate::peers::EST_ROOT_STORE
                    })
            } else {
                0
            },
            // ADR 0049 rule 15: the network group table, allocated once at start-up, and the
            // global bucket; nothing when `ingest_bytes_per_hour` is 0.
            if self.ingest_bytes_per_hour == 0 {
                0
            } else {
                self.ingest_group_max
                    .saturating_mul(EST_GROUP_ENTRY)
                    .saturating_add(EST_INGEST_FIXED)
            },
            // ADR 0052 rule 21: only when `deny_file` is set.
            if self.deny_file.is_some() {
                self.deny_max_entries.saturating_mul(2 * EST_DENY_ENTRY)
            } else {
                0
            },
            // ADR 0054 rule 35: only with `ws_enabled`.
            if self.ws_enabled {
                self.subscription_bytes()
            } else {
                0
            },
        ]
        .into_iter()
        .fold(0, u64::saturating_add)
    }

    /// ADR 0054 rules 29 and 35: the subscription registry, the fan-out queue and the network
    /// group counts, plus, for each subscription connection, what its buffers take beyond the
    /// per-connection term of ADR 0018 rule 35.
    #[must_use]
    pub fn subscription_bytes(&self) -> u64 {
        let per_conn = crate::subscribe::CONNECTION_BYTES;
        let term = self.max_header_bytes + EST_LARGEST_RESPONSE;
        [
            self.ws_max_connections
                .saturating_mul(self.ws_max_subscriptions)
                .saturating_mul(crate::subscribe::EST_SUBSCRIPTION),
            crate::subscribe::FANOUT_QUEUE as u64 * crate::subscribe::EST_FANOUT_ENTRY,
            self.ws_max_connections
                .saturating_mul(crate::subscribe::EST_GROUP_COUNT),
            self.ws_max_connections
                .saturating_mul(per_conn.saturating_sub(term)),
        ]
        .into_iter()
        .fold(0, u64::saturating_add)
    }

    /// Every setting with its effective value and source, for the `setting` events. No setting
    /// is a secret.
    pub fn effective_values(&self) -> impl Iterator<Item = (&'static str, String, Source)> + '_ {
        self.sources
            .iter()
            .map(|(name, source)| (*name, self.value_text(name).unwrap_or_default(), *source))
    }

    /// Mirror review L-2: the names of the environment variables the archive copy reads its
    /// credentials from, when it is configured; none otherwise.
    #[must_use]
    pub fn credential_vars(&self) -> Vec<&str> {
        if self.mirror_endpoint.is_none() {
            return Vec::new();
        }
        let mut v = vec![
            self.mirror_access_key_ref.as_str(),
            self.mirror_secret_key_ref.as_str(),
        ];
        v.extend(self.mirror_session_token_ref.as_deref());
        v
    }

    /// ADR 0021 rule 22: the most bytes the logger can write in the 24 hours after start-up,
    /// outside the start-up, shutdown and `fatal` lines.
    #[must_use]
    pub fn log_bound_bytes_per_day(&self) -> u64 {
        let line = crate::log::MAX_LINE as u64;
        (self.log_burst + self.log_rate_per_min * 1_440 + 1_440) * line
    }
}

/// The default of `index_max_readers` (ADR 0018 rules 15 to 17: 2, provisional, on every target
/// until the Linux musl measurement).
pub const DEFAULT_INDEX_MAX_READERS: u64 = 2;

/// ADR 0019 rule 36.2 for the integer settings: environment, else file (both in `values`, which
/// keeps only the other keys afterwards), else profile, else built-in default. Computed defaults
/// stay `None`.
fn resolve_ints(
    values: &mut BTreeMap<String, Raw>,
    profile: Profile,
) -> Result<(Ints, BTreeMap<&'static str, Source>), ConfigError> {
    let mut ints = Ints::default();
    let mut sources = BTreeMap::new();
    let mut keys: Vec<String> = values.keys().cloned().collect();
    keys.retain(|k| !OTHER_KEYS.contains(&k.as_str()));
    for key in keys {
        let Some(raw) = values.remove(&key) else {
            continue;
        };
        let Some(slot) = ints.slot(&key) else {
            return Err(ConfigError::UnknownKey(key));
        };
        *slot.value = Some(raw.int(slot.name, slot.min, slot.max)?);
        sources.insert(slot.name, raw.source());
    }
    if let Some(t @ 1..MIN_STATS_INTERVAL_MS) = ints.stats_interval_ms {
        return Err(ConfigError::Invalid {
            setting: "stats_interval_ms",
            reason: format!(
                "{t} is outside {MIN_STATS_INTERVAL_MS} to 86400000; 0 is also valid and disables \
                 the stats line"
            ),
        });
    }
    if let Some(ttl @ 1..MIN_BLOCK_TTL_MS) = ints.block_ttl_ms {
        let max = ints.slot("block_ttl_ms").map_or(u64::MAX, |s| s.max);
        return Err(ConfigError::Invalid {
            setting: "block_ttl_ms",
            reason: format!(
                "{ttl} is outside {MIN_BLOCK_TTL_MS} to {max}; 0 is also valid and disables \
                 eviction by age"
            ),
        });
    }
    for name in INT_NAMES {
        let Some(slot) = ints.slot(name) else {
            continue;
        };
        if slot.value.is_some() {
            continue;
        }
        let (value, from) = match profile.value(slot.name) {
            Some(v) => (Some(v), Source::Profile),
            None => (slot.default, Source::Default),
        };
        *slot.value = value;
        sources.insert(slot.name, from);
    }
    Ok((ints, sources))
}

fn is_known(name: &str) -> bool {
    OTHER_KEYS.contains(&name) || Ints::default().slot(name).is_some()
}

fn parse_profile(r: Option<Raw>) -> Result<Profile, ConfigError> {
    let Some(r) = r else {
        return Ok(Profile::Small);
    };
    let name = r.string("profile")?;
    Profile::parse(&name).ok_or_else(|| ConfigError::Invalid {
        setting: "profile",
        reason: format!("`{name}` is not small, standard or large"),
    })
}

/// A string setting with a fixed set of values; `None` when it is not set.
fn parse_choice<T>(
    r: Option<Raw>,
    setting: &'static str,
    parse: fn(&str) -> Option<T>,
    names: &[&str],
) -> Result<Option<T>, ConfigError> {
    let Some(r) = r else {
        return Ok(None);
    };
    let s = r.string(setting)?;
    parse(&s).map(Some).ok_or_else(|| ConfigError::Invalid {
        setting,
        reason: format!("`{s}` is not {}", names.join(", ")),
    })
}

/// Security review L-3: `log_format` alone, from `SBTP_RELAY_LOG_FORMAT` or else the file named
/// by `--config` or `SBTP_RELAY_CONFIG`, before the settings are loaded, so that the `start` line
/// and an early `fatal` line have the configured form. Text when it cannot be read; an invalid
/// value is still reported by [`Settings::load`].
#[must_use]
pub fn early_log_format(args: &[OsString], env: &[(OsString, OsString)]) -> Format {
    let var = |k: &str| {
        env.iter()
            .find(|(n, _)| n.to_str() == Some(k))
            .and_then(|(_, v)| v.to_str())
    };
    if let Some(v) = var("SBTP_RELAY_LOG_FORMAT") {
        return Format::parse(v).unwrap_or(Format::Text);
    }
    parse_args(args.iter().cloned())
        .ok()
        .flatten()
        .or_else(|| var(ENV_CONFIG).map(PathBuf::from))
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| text.parse::<toml::Table>().ok())
        .and_then(|t| t.get("log_format")?.as_str().and_then(Format::parse))
        .unwrap_or(Format::Text)
}

/// A boolean setting: a TOML boolean, or `true` or `false` in the environment; `None` when it is
/// not set.
fn parse_bool(r: Option<Raw>, setting: &'static str) -> Result<Option<bool>, ConfigError> {
    match r {
        None => Ok(None),
        Some(Raw::Toml(toml::Value::Boolean(b))) => Ok(Some(b)),
        Some(Raw::Env(s)) if s == "true" => Ok(Some(true)),
        Some(Raw::Env(s)) if s == "false" => Ok(Some(false)),
        Some(_) => Err(ConfigError::Invalid {
            setting,
            reason: "expected true or false".into(),
        }),
    }
}

fn parse_listen(r: Option<Raw>) -> Result<SocketAddr, ConfigError> {
    let Some(r) = r else {
        return Ok(SocketAddr::from(([127, 0, 0, 1], 8080)));
    };
    r.string("listen")?
        .parse()
        .map_err(|_| ConfigError::Invalid {
            setting: "listen",
            reason: "expected an address and port, such as 127.0.0.1:8080".into(),
        })
}

/// ADR 0044 rule 1: an RFC 9110 §5.1 field name (a token) of 1 to 64 bytes, compared without
/// regard to case (kept lowercase), never `X-Forwarded-For` or `Forwarded`. Absent: off.
fn parse_client_ip_header(r: Option<Raw>) -> Result<Option<String>, ConfigError> {
    let Some(r) = r else {
        return Ok(None);
    };
    let s = r.string("client_ip_header")?.to_ascii_lowercase();
    let invalid = |reason: &str| ConfigError::Invalid {
        setting: "client_ip_header",
        reason: reason.into(),
    };
    let tchar = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    if s.is_empty() || s.len() > 64 || !s.bytes().all(tchar) {
        return Err(invalid(
            "expected an HTTP field name of 1 to 64 token characters",
        ));
    }
    if s == "x-forwarded-for" || s == "forwarded" {
        return Err(invalid(
            "X-Forwarded-For and Forwarded are address chains, not a single-value header \
             (ADR 0044 rule 1); leave client_ip_header unset to read X-Forwarded-For",
        ));
    }
    Ok(Some(s))
}

/// ADR 0048 rules 5 and 20: relay URLs, normalised, without duplicates.
fn parse_peers(r: Option<Raw>) -> Result<Vec<PeerUrl>, ConfigError> {
    let Some(r) = r else {
        return Ok(Vec::new());
    };
    let mut out: Vec<PeerUrl> = Vec::new();
    for (n, item) in r.list("peers")?.into_iter().enumerate() {
        // The reason shows the URL without its userinfo (security review 2026-11-21 I-2); the
        // position finds it in the list.
        let url = PeerUrl::parse(&item).map_err(|reason| ConfigError::Invalid {
            setting: "peers",
            reason: format!("item {}: {reason}", n + 1),
        })?;
        if out.contains(&url) {
            return Err(ConfigError::Invalid {
                setting: "peers",
                reason: format!("`{item}` is listed twice (after normalisation)"),
            });
        }
        out.push(url);
    }
    Ok(out)
}

/// A relay URL setting (ADR 0048 rule 14, ADR 0050 rules 15 and 23); empty is `None`.
fn parse_url(r: Option<Raw>, setting: &'static str) -> Result<Option<PeerUrl>, ConfigError> {
    let Some(r) = r else {
        return Ok(None);
    };
    let s = r.string(setting)?;
    if s.is_empty() {
        return Ok(None);
    }
    PeerUrl::parse(&s)
        .map(Some)
        .map_err(|reason| ConfigError::Invalid { setting, reason })
}

/// A string setting checked by `valid`; `default` when not set.
fn parse_text(
    r: Option<Raw>,
    setting: &'static str,
    default: &str,
    valid: fn(&str) -> Result<(), &'static str>,
) -> Result<String, ConfigError> {
    let Some(r) = r else {
        return Ok(default.to_owned());
    };
    let s = r.string(setting)?;
    valid(&s).map_err(|why| ConfigError::Invalid {
        setting,
        reason: format!("`{s}`: {why}"),
    })?;
    Ok(s)
}

/// ADR 0050 rule 28: empty (off) or 3 to 63 characters of `a-z 0-9 . -`.
fn valid_bucket(s: &str) -> Result<(), &'static str> {
    let shape = (3..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    if s.is_empty() || shape {
        Ok(())
    } else {
        Err("a bucket name is 3 to 63 characters of a-z, 0-9, `.` and `-`")
    }
}

/// ADR 0050 rule 28: 1 to 32 characters of `a-z 0-9 -`.
fn valid_region(s: &str) -> Result<(), &'static str> {
    if (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        Ok(())
    } else {
        Err("a region is 1 to 32 characters of a-z, 0-9 and `-`")
    }
}

/// ADR 0050 rule 28: empty, or at most 256 characters of `A-Z a-z 0-9 / . _ -` ending with `/`.
/// Also refused here: an empty, `.` or `..` segment (a leading `/` included), which a proxy or
/// a CDN may normalise away, so that the object would not be found under the public URL.
fn valid_prefix(s: &str) -> Result<(), &'static str> {
    if s.is_empty() {
        return Ok(());
    }
    let chars = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'));
    let segments = s.strip_suffix('/').is_some_and(|inner| {
        inner
            .split('/')
            .all(|g| !g.is_empty() && g != "." && g != "..")
    });
    if s.len() <= 256 && chars && segments {
        Ok(())
    } else {
        Err(
            "a prefix is at most 256 characters of A-Z, a-z, 0-9, `/`, `.`, `_` and `-`, \
             ends with `/`, and has no empty, `.` or `..` segment",
        )
    }
}

/// ADR 0050 rule 22: the name of an environment variable, never a credential. The value is not
/// repeated in the error: it may be a key written in the wrong setting. Empty is `None`.
fn parse_var_name(r: Option<Raw>, setting: &'static str) -> Result<Option<String>, ConfigError> {
    let Some(r) = r else {
        return Ok(None);
    };
    let s = Zeroizing::new(r.string(setting)?);
    if s.is_empty() {
        return Ok(None);
    }
    let shape = s.len() <= 64
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_uppercase() || b == b'_')
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !shape || s.starts_with(ENV_PREFIX) {
        return Err(ConfigError::Invalid {
            setting,
            reason: "must be the name of an environment variable (A-Z, 0-9 and `_`, at most 64 \
                     characters, not starting with a digit or SBTP_RELAY_), never a credential \
                     (ADR 0050 rule 22)"
                .into(),
        });
    }
    Ok(Some(s.to_string()))
}

/// A non-empty path.
fn parse_path(r: &Raw, setting: &'static str) -> Result<PathBuf, ConfigError> {
    let s = r.string(setting)?;
    if s.is_empty() {
        return Err(ConfigError::Invalid {
            setting,
            reason: "empty path".into(),
        });
    }
    Ok(PathBuf::from(s))
}

fn parse_data_dir(r: Option<Raw>) -> Result<PathBuf, ConfigError> {
    let Some(r) = r else {
        return Ok(PathBuf::from("data"));
    };
    let s = r.string("data_dir")?;
    if s.is_empty() {
        return Err(ConfigError::Invalid {
            setting: "data_dir",
            reason: "empty path".into(),
        });
    }
    Ok(PathBuf::from(s))
}

fn parse_cors(r: Option<Raw>) -> Result<CorsOrigins, ConfigError> {
    match r {
        None => Ok(CorsOrigins::Any),
        Some(Raw::Toml(toml::Value::String(s)) | Raw::Env(s)) if s.trim() == "*" => {
            Ok(CorsOrigins::Any)
        }
        Some(r) => Ok(CorsOrigins::List(parse_origins(
            &r.list("cors_allow_origins")?,
        )?)),
    }
}

fn parse_cidrs(
    r: Option<Raw>,
    setting: &'static str,
    default: &[&str],
    zero_prefix: bool,
) -> Result<Vec<Cidr>, ConfigError> {
    let Some(r) = r else {
        return Ok(default
            .iter()
            .filter_map(|s| Cidr::parse(s, zero_prefix).ok())
            .collect());
    };
    r.list(setting)?
        .iter()
        .map(|s| {
            Cidr::parse(s, zero_prefix).map_err(|reason| ConfigError::Invalid { setting, reason })
        })
        .collect()
}

fn parse_args<A: IntoIterator<Item = OsString>>(args: A) -> Result<Option<PathBuf>, ConfigError> {
    let mut args = args.into_iter();
    let mut path = None;
    while let Some(a) = args.next() {
        if a == "--config" && path.is_none() {
            let p = args
                .next()
                .ok_or_else(|| ConfigError::Args("--config needs a path".into()))?;
            path = Some(PathBuf::from(p));
        } else {
            return Err(ConfigError::Args(format!(
                "unexpected argument `{}`; usage: sbtp-relay [--config <path>]",
                a.to_string_lossy()
            )));
        }
    }
    Ok(path)
}

/// ADR 0012 rule 23: `scheme://host[:port]`. Lowercased as a whole, because browsers serialise the
/// scheme and host of `Origin` in lowercase and the comparison is byte for byte.
fn parse_origins(items: &[String]) -> Result<Vec<HeaderValue>, ConfigError> {
    items
        .iter()
        .map(|o| {
            let lower = o.to_ascii_lowercase();
            let valid = lower.split_once("://").is_some_and(|(scheme, rest)| {
                !scheme.is_empty()
                    && scheme.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"+-.".contains(&b)
                    })
                    && !rest.is_empty()
                    && rest.bytes().all(|b| b.is_ascii_graphic() && b != b'/')
            });
            valid
                .then(|| HeaderValue::from_str(&lower).ok())
                .flatten()
                .ok_or_else(|| ConfigError::Invalid {
                    setting: "cors_allow_origins",
                    reason: format!("`{o}` is not `*` or an origin scheme://host[:port]"),
                })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn soft_open_file_limit() -> Option<u64> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    let soft = line
        .get("Max open files".len()..)?
        .split_whitespace()
        .next()?;
    if soft == "unlimited" {
        Some(u64::MAX)
    } else {
        soft.parse().ok()
    }
}

#[cfg(not(target_os = "linux"))]
fn soft_open_file_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn int_names_cover_every_slot() {
        let mut raw = Ints::default();
        for n in INT_NAMES {
            assert!(raw.slot(n).is_some(), "{n}");
        }
        // 67 integer settings plus the 29 others: ADRs 0007, 0012, 0013, 0018, 0019, 0021, 0044,
        // 0046, 0048, 0049, 0050, 0052 and 0054.
        assert_eq!(INT_NAMES.len() + OTHER_KEYS.len(), 96);
    }

    /// ADR 0050 rule 28: without `object-store`, a `mirror_*` setting given at its default is
    /// accepted, any other value stops the start-up.
    #[cfg(not(feature = "object-store"))]
    #[test]
    fn mirror_settings_without_the_feature() {
        let load = |k: &str, v: &str| {
            Settings::load(
                Vec::<std::ffi::OsString>::new(),
                vec![(format!("SBTP_RELAY_{k}").into(), v.into())],
            )
        };
        assert!(load("MIRROR_INFO", "true").is_ok());
        assert!(load("MIRROR_REGION", "us-east-1").is_ok());
        for (k, v) in [
            ("MIRROR_ENDPOINT", "https://s3.example"),
            ("MIRROR_INFO", "false"),
            ("MIRROR_MAX_IN_FLIGHT", "2"),
        ] {
            assert!(
                matches!(load(k, v), Err(ConfigError::Invalid { setting, .. }) if setting.starts_with("mirror_")),
                "{k}"
            );
        }
    }

    /// ADR 0044 rule 1: a field name of 1 to 64 token bytes, kept lowercase; the two address
    /// chains are refused whatever their case; the note of rule 7 is written when it is set.
    #[test]
    fn client_ip_header_setting() {
        let load = |v: &str| {
            Settings::load(
                Vec::<std::ffi::OsString>::new(),
                vec![("SBTP_RELAY_CLIENT_IP_HEADER".into(), v.into())],
            )
        };
        let s = load("CF-Connecting-IP").unwrap();
        assert_eq!(s.client_ip_header.as_deref(), Some("cf-connecting-ip"));
        assert!(
            s.config_notes()
                .iter()
                .any(|n| n.code == "client_ip_header" && n.msg.contains("cf-connecting-ip"))
        );
        for bad in [
            "X-Forwarded-For",
            "x-forwarded-for",
            "Forwarded",
            "",
            "two words",
            "a:b",
            &"x".repeat(65),
        ] {
            assert!(
                matches!(
                    load(bad),
                    Err(ConfigError::Invalid {
                        setting: "client_ip_header",
                        ..
                    })
                ),
                "{bad}"
            );
        }
        assert!(load(&"x".repeat(64)).is_ok());
        let off = Settings::finish(BTreeMap::new()).unwrap();
        assert_eq!(off.client_ip_header, None);
        assert!(
            off.config_notes()
                .iter()
                .all(|n| n.code != "client_ip_header")
        );
    }

    /// Every setting has a source and a logged value, read from its typed field.
    #[test]
    fn every_setting_is_logged_with_its_value() {
        let s = Settings::finish(BTreeMap::new()).unwrap();
        for name in INT_NAMES.iter().chain(OTHER_KEYS.iter()) {
            assert!(s.source(name).is_some(), "{name}");
            assert!(s.value_text(name).is_some(), "{name}");
        }
        assert_eq!(s.sources.len(), INT_NAMES.len() + OTHER_KEYS.len());
        // Every profiled setting has a built-in default: the `small` column.
        for (name, _) in PROFILE_VALUES {
            assert!(Profile::Small.value(name).is_some(), "{name}");
        }
    }

    #[test]
    fn cidr_parsing() {
        let parse = |s| Cidr::parse(s, true);
        assert!(parse("10.0.0.0/8").is_ok());
        assert!(parse("10.0.0.1/8").is_err());
        assert!(parse("10.0.0.0/33").is_err());
        assert!(parse("10.0.0.0").is_err());
        let v6 = parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        assert!(
            parse("0.0.0.0/0")
                .unwrap()
                .contains("192.0.2.1".parse().unwrap())
        );
        // ADR 0020 rule 13: a prefix of 0 only where allowed.
        assert!(Cidr::parse("0.0.0.0/0", false).is_err());
        assert!(Cidr::parse("::/0", false).is_err());
        // ADR 0020 rule 19: an IPv4-mapped block is refused, with its IPv4 form.
        for (block, ipv4) in [
            ("::ffff:10.0.0.0/104", "`10.0.0.0/8`"),
            ("::ffff:192.0.2.7/128", "`192.0.2.7/32`"),
            ("::ffff:0:0/96", "`0.0.0.0/0`"),
        ] {
            let e = parse(block).unwrap_err();
            assert!(e.contains(ipv4), "{e}");
        }
        // Code review CR4: never a prefix-0 suggestion where a prefix of 0 is refused.
        let e = Cidr::parse("::ffff:0:0/96", false).unwrap_err();
        assert!(e.contains("IPv4-mapped") && !e.contains("/0"), "{e}");
        assert!(parse("::/80").is_ok(), "not inside ::ffff:0:0/96");
        let broad = |s| parse(s).unwrap().is_broad();
        assert!(broad("10.0.0.0/15") && !broad("10.0.0.0/16"));
        assert!(broad("2001:d00::/31") && !broad("2001:db8::/32"));
    }
}
