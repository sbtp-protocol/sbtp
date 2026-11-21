//! Settings (ADR 0018 rules 6, 7 and 22) and start-up order (ADR 0003 rule 16).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::ffi::OsString;

use axum::http::HeaderValue;
use common::{env, tmp_dir};
use sbtp_core::SelfTestError;
use sbtp_relay::StartError;
use sbtp_relay::config::{Cidr, ConfigError, CorsOrigins, Profile, Settings, Source};

fn load(args: &[&str], pairs: &[(&str, &str)]) -> Result<Settings, ConfigError> {
    let mut e = env(pairs);
    if !pairs.iter().any(|(k, _)| *k == "MIN_POW_DIFFICULTY") {
        e.extend(env(&[("MIN_POW_DIFFICULTY", "16")]));
    }
    Settings::load(args.iter().map(OsString::from), e)
}

/// The messages of the start-up warnings.
fn warnings(s: &Settings) -> Vec<String> {
    s.config_warnings().into_iter().map(|w| w.msg).collect()
}

/// The messages of the start-up notes.
fn notes(s: &Settings) -> Vec<String> {
    s.config_notes().into_iter().map(|w| w.msg).collect()
}

fn file(name: &str, text: &str) -> String {
    let dir = tmp_dir(name);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("relay.toml");
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_owned()
}

#[test]
fn defaults_are_the_small_vps_column() {
    let s = load(&[], &[]).unwrap();
    assert_eq!(s.listen.to_string(), "127.0.0.1:8080");
    assert_eq!(s.data_dir.to_str(), Some("data"));
    // ADR 0007, 0012, 0013.
    assert_eq!(s.min_pow_difficulty, 16);
    assert_eq!(s.max_future_ms, 300_000);
    assert_eq!(s.max_query_limit, 1_000);
    assert_eq!(s.cors_allow_origins, CorsOrigins::Any);
    // ADR 0046 rules 1, 2 and 24.
    assert_eq!(s.block_ttl_ms, None);
    assert!(s.demand_eviction);
    assert_eq!(
        (
            s.demand_high_water_pct,
            s.demand_low_water_pct,
            s.demand_epoch_ms,
            s.demand_touch_max
        ),
        (90, 80, 86_400_000, 16_384)
    );
    assert_eq!(s.profile, Profile::Small);
    assert_eq!(
        (
            s.max_connections_per_client,
            s.max_connection_age_ms,
            s.max_requests_per_connection
        ),
        (8, 300_000, 1_000)
    );
    assert_eq!(s.max_store_bytes, 1 << 30);
    assert_eq!(s.sweep_interval_ms, 60_000);
    assert_eq!(s.sweep_batch, 1_000);
    assert_eq!(s.index_cache_bytes, 4 << 20);
    // ADR 0018 rule 22.
    let cpus = std::thread::available_parallelism().unwrap().get() as u64;
    assert_eq!(s.worker_threads, cpus.clamp(1, 256));
    assert_eq!(s.max_blocking_threads, 10);
    assert_eq!(s.max_connections, 32);
    assert_eq!(s.max_header_bytes, 16_384);
    assert_eq!(
        (
            s.header_timeout_ms,
            s.body_timeout_ms,
            s.request_timeout_ms,
            s.idle_timeout_ms
        ),
        (5_000, 10_000, 15_000, 30_000)
    );
    assert_eq!((s.index_max_readers, s.index_max_queue), (2, 32));
    assert_eq!((s.block_max_readers, s.block_max_queue), (4, 32));
    assert_eq!((s.put_max_in_flight, s.put_max_queue), (4, 16));
    assert_eq!(s.put_max_in_flight_per_client, 2);
    assert_eq!((s.queue_timeout_ms, s.shed_retry_after_s), (1_000, 2));
    assert_eq!((s.rate_block_per_min, s.rate_block_burst), (3_000, 200));
    assert_eq!((s.rate_query_per_min, s.rate_query_burst), (300, 20));
    assert_eq!((s.rate_put_per_min, s.rate_put_burst), (30, 20));
    assert_eq!(s.rate_limit_max_clients, 4_096);
    assert_eq!(s.rate_limit_exempt, Vec::<Cidr>::new());
    assert_eq!(s.client_ipv6_prefix, 64);
    let proxies: Vec<String> = s.trusted_proxies.iter().map(Cidr::to_string).collect();
    assert_eq!(proxies, ["127.0.0.1/32", "::1/128"]);
    assert_eq!(s.block_cache_bytes, 2 << 20);
    assert_eq!(s.open_files_needed(), 32 + 4 + 4 + 32);
}

#[test]
fn file_overrides_defaults_and_environment_overrides_file() {
    let path = file(
        "precedence",
        "max_connections = 10\nbody_timeout_ms = 2000\ntrusted_proxies = [\"10.0.0.0/8\"]\n\
         cors_allow_origins = [\"https://A.EXAMPLE:8443\"]\nlisten = \"127.0.0.1:9000\"\n",
    );
    let s = load(
        &["--config", &path],
        &[
            ("MAX_CONNECTIONS", "20"),
            ("RATE_LIMIT_EXEMPT", "192.0.2.0/24, ::1/128"),
        ],
    )
    .unwrap();
    assert_eq!(s.max_connections, 20, "environment wins over the file");
    assert_eq!(s.body_timeout_ms, 2_000, "file wins over the default");
    assert_eq!(s.idle_timeout_ms, 30_000, "default");
    assert_eq!(s.trusted_proxies[0].to_string(), "10.0.0.0/8");
    assert_eq!(s.rate_limit_exempt.len(), 2);
    assert_eq!(
        s.cors_allow_origins,
        CorsOrigins::List(vec![HeaderValue::from_static("https://a.example:8443")])
    );
    assert_eq!(s.listen.port(), 9000);

    // The file can also come from SBTP_RELAY_CONFIG; `--config` wins over it.
    let s = load(&[], &[("CONFIG", &path)]).unwrap();
    assert_eq!(s.max_connections, 10);
    let other = file("precedence-other", "max_connections = 11\n");
    let s = load(&["--config", &other], &[("CONFIG", &path)]).unwrap();
    assert_eq!(s.max_connections, 11);
    // A list from the environment: empty string is the empty list; `*` is the wildcard.
    let s = load(&[], &[("CORS_ALLOW_ORIGINS", ""), ("TRUSTED_PROXIES", "")]).unwrap();
    assert_eq!(s.cors_allow_origins, CorsOrigins::List(vec![]));
    assert_eq!(s.trusted_proxies, Vec::<Cidr>::new());
    let s = load(&[], &[("CORS_ALLOW_ORIGINS", "*")]).unwrap();
    assert_eq!(s.cors_allow_origins, CorsOrigins::Any);
}

fn err(args: &[&str], pairs: &[(&str, &str)]) -> ConfigError {
    load(args, pairs).unwrap_err()
}

#[test]
fn bad_values_stop_start_up_and_name_the_setting() {
    let unknown = file("unknown", "max_conections = 3\n");
    assert!(
        matches!(err(&["--config", &unknown], &[]), ConfigError::UnknownKey(k) if k == "max_conections")
    );
    assert!(
        matches!(err(&[], &[("MAX_CONECTIONS", "3")]), ConfigError::UnknownKey(k) if k == "SBTP_RELAY_MAX_CONECTIONS")
    );
    assert!(matches!(
        err(&[], &[("max_connections", "3")]),
        ConfigError::UnknownKey(_)
    ));

    let typed = file("typed", "max_connections = \"many\"\n");
    let e = err(&["--config", &typed], &[]);
    assert!(matches!(
        e,
        ConfigError::Invalid {
            setting: "max_connections",
            ..
        }
    ));
    assert!(e.to_string().contains("max_connections"));
    assert!(matches!(
        err(&[], &[("IDLE_TIMEOUT_MS", "30s")]),
        ConfigError::Invalid {
            setting: "idle_timeout_ms",
            ..
        }
    ));
    assert!(matches!(
        err(&[], &[("IDLE_TIMEOUT_MS", "-1")]),
        ConfigError::Invalid {
            setting: "idle_timeout_ms",
            ..
        }
    ));

    for (k, v, setting) in [
        ("MAX_CONNECTIONS", "0", "max_connections"),
        ("MAX_CONNECTIONS", "65536", "max_connections"),
        ("MAX_HEADER_BYTES", "8191", "max_header_bytes"),
        ("HEADER_TIMEOUT_MS", "999", "header_timeout_ms"),
        ("CLIENT_IPV6_PREFIX", "65", "client_ipv6_prefix"),
        ("MIN_POW_DIFFICULTY", "257", "min_pow_difficulty"),
        ("MAX_QUERY_LIMIT", "1001", "max_query_limit"),
        ("INDEX_CACHE_BYTES", "1048575", "index_cache_bytes"),
        (
            "WORKER_THREADS",
            "99999999999999999999999",
            "worker_threads",
        ),
    ] {
        let e = err(&[], &[(k, v)]);
        assert!(
            matches!(&e, ConfigError::OutOfRange { setting: s, .. } if *s == setting),
            "{k}={v}: {e}"
        );
        assert!(e.to_string().contains(setting));
    }
    let negative = file("negative", "max_connections = -1\n");
    assert!(matches!(
        err(&["--config", &negative], &[]),
        ConfigError::OutOfRange {
            setting: "max_connections",
            ..
        }
    ));
}

#[test]
fn broken_constraints_and_bad_sources_stop_start_up() {
    for (pairs, needle) in [
        (
            &[("QUEUE_TIMEOUT_MS", "2000"), ("REQUEST_TIMEOUT_MS", "2000")][..],
            "queue_timeout_ms",
        ),
        (&[("HEADER_TIMEOUT_MS", "20000")][..], "header_timeout_ms"),
        (&[("BODY_TIMEOUT_MS", "20000")][..], "body_timeout_ms"),
        (
            &[("PUT_MAX_IN_FLIGHT_PER_CLIENT", "5")][..],
            "put_max_in_flight_per_client",
        ),
        (&[("MAX_BLOCKING_THREADS", "9")][..], "max_blocking_threads"),
        (&[("PUT_MAX_IN_FLIGHT", "511")][..], "max_blocking_threads"),
    ] {
        let e = err(&[], pairs);
        assert!(
            matches!(&e, ConfigError::Constraint(m) if m.contains(needle)),
            "{e}"
        );
    }

    for (k, v, setting) in [
        ("TRUSTED_PROXIES", "10.0.0.1/8", "trusted_proxies"),
        ("RATE_LIMIT_EXEMPT", "not-an-ip/8", "rate_limit_exempt"),
        (
            "CORS_ALLOW_ORIGINS",
            "https://a.example/",
            "cors_allow_origins",
        ),
        (
            "CORS_ALLOW_ORIGINS",
            "*,https://a.example",
            "cors_allow_origins",
        ),
        ("LISTEN", "localhost", "listen"),
    ] {
        let e = err(&[], &[(k, v)]);
        assert!(
            matches!(&e, ConfigError::Invalid { setting: s, .. } if *s == setting),
            "{k}={v}: {e}"
        );
    }

    assert!(matches!(err(&["--verbose"], &[]), ConfigError::Args(_)));
    assert!(matches!(err(&["--config"], &[]), ConfigError::Args(_)));
    assert!(matches!(
        err(&["--config", "/nonexistent/relay.toml"], &[]),
        ConfigError::File(_)
    ));
    let broken = file("broken", "max_connections = \n");
    assert!(matches!(
        err(&["--config", &broken], &[]),
        ConfigError::File(_)
    ));
}

fn failing() -> Result<(), SelfTestError> {
    Err(SelfTestError::SPlusLAccepted)
}

#[test]
fn shipped_self_test_passes() {
    sbtp_core::self_test().unwrap();
}

/// ADR 0003 rule 16: the relay refuses to start when the self-test fails, before it reads its
/// settings, opens anything or listens.
#[test]
fn failed_self_test_refuses_start() {
    let data = tmp_dir("self-test");
    let e = env(&[
        ("MIN_POW_DIFFICULTY", "16"),
        ("LISTEN", "127.0.0.1:0"),
        ("DATA_DIR", data.to_str().unwrap()),
    ]);
    let mut listened = false;
    let r = sbtp_relay::run(
        failing,
        Vec::<OsString>::new(),
        e,
        || Ok(tokio::sync::mpsc::unbounded_channel::<()>().1),
        |_| listened = true,
    );
    assert!(matches!(
        r,
        Err(StartError::SelfTest(SelfTestError::SPlusLAccepted))
    ));
    assert!(!listened);
    assert!(
        !data.exists(),
        "nothing may be created before the self-test"
    );
}

/// ADR 0018 rule 7: a bad setting stops the relay before it opens the index or listens.
#[test]
fn bad_setting_refuses_start_before_the_index() {
    let data = tmp_dir("bad-setting");
    let e = env(&[
        ("MIN_POW_DIFFICULTY", "16"),
        ("MAX_CONNECTIONS", "0"),
        ("DATA_DIR", data.to_str().unwrap()),
    ]);
    let mut listened = false;
    let r = sbtp_relay::run(
        sbtp_core::self_test,
        Vec::<OsString>::new(),
        e,
        || Ok(tokio::sync::mpsc::unbounded_channel::<()>().1),
        |_| listened = true,
    );
    assert!(matches!(
        r,
        Err(StartError::Config(ConfigError::OutOfRange {
            setting: "max_connections",
            ..
        }))
    ));
    assert!(!listened);
    assert!(!data.exists());
}

/// Security review F-3: a start-up error after the index is open (here the block store, whose
/// `blocks` is not a directory) still flushes and closes the index: it opens again afterwards.
#[test]
fn start_up_error_closes_the_index() {
    use sbtp_relay::index::{IndexBackend, RedbIndex};
    let data = tmp_dir("store-error");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("blocks"), b"not a directory").unwrap();
    let e = env(&[
        ("MIN_POW_DIFFICULTY", "16"),
        ("LISTEN", "127.0.0.1:0"),
        ("DATA_DIR", data.to_str().unwrap()),
    ]);
    let mut listened = false;
    let r = sbtp_relay::run(
        sbtp_core::self_test,
        Vec::<OsString>::new(),
        e,
        || Ok(tokio::sync::mpsc::unbounded_channel::<()>().1),
        |_| listened = true,
    );
    assert!(
        matches!(r, Err(StartError::Io("opening the block store", _))),
        "{r:?}"
    );
    assert!(!listened);
    let path = data.join("index.redb");
    assert!(path.exists(), "the index was opened");
    let index = RedbIndex::open(&path, 1 << 20).expect("closed by `run`");
    // The check discriminates: an index still open in this process cannot be opened again.
    assert!(RedbIndex::open(&path, 1 << 20).is_err());
    index.close().unwrap();
}

/// ADR 0019 rules 1 and 2: no configuration starts with difficulty 16; 0 is valid when set, with
/// a warning. Rules 9 and 38: the other start-up warnings.
#[test]
fn difficulty_defaults_to_16_and_0_warns() {
    let s = Settings::load(Vec::<OsString>::new(), Vec::new()).unwrap();
    assert_eq!(s.min_pow_difficulty, 16);
    assert_eq!(s.source("min_pow_difficulty"), Some(Source::Default));
    assert_eq!(warnings(&s), Vec::<String>::new());

    let s = load(&[], &[("MIN_POW_DIFFICULTY", "0")]).unwrap();
    assert_eq!(s.min_pow_difficulty, 0);
    assert!(
        warnings(&s)
            .iter()
            .any(|w| w.contains("min_pow_difficulty = 0")),
        "{:?}",
        warnings(&s)
    );

    let s = load(&[], &[("LISTEN", "0.0.0.0:8080")]).unwrap();
    assert!(warnings(&s).iter().any(|w| w.contains("not a loopback")));
    let s = load(&[], &[("LISTEN", "[::1]:0")]).unwrap();
    assert_eq!(warnings(&s), Vec::<String>::new());

    let store = |pairs: &[(&str, &str)]| {
        warnings(&load(&[], pairs).unwrap())
            .iter()
            .any(|w| w.contains("max_store_bytes"))
    };
    assert!(store(&[("PROFILE", "standard")]));
    assert!(store(&[("PROFILE", "large")]));
    assert!(!store(&[("PROFILE", "small")]));
    assert!(!store(&[
        ("PROFILE", "large"),
        ("MAX_STORE_BYTES", "1073741824")
    ]));
}

/// `key = value` from the environment and from the file: both accept or both refuse (ADR 0019
/// rule 5).
fn both(key: &str, value: &str) -> [Result<Settings, ConfigError>; 2] {
    let path = file("range", &format!("{key} = {value}\n"));
    [
        load(&[], &[(&key.to_ascii_uppercase(), value)]),
        load(&["--config", &path], &[]),
    ]
}

/// ADR 0019 rules 4, 5 and 28: each bound, on both sides, from both sources.
#[test]
fn ranges_of_adr_0019() {
    let max = "9223372036854775807";
    let over = "9223372036854775808";
    for (key, refused, accepted) in [
        (
            "max_future_ms",
            &["999", "86400001"][..],
            &["1000", "86400000"][..],
        ),
        (
            "block_ttl_ms",
            &["1", "59999", "315360000001"],
            &["0", "60000", "315360000000"],
        ),
        ("max_store_bytes", &["4194303", over], &["4194304", max]),
        (
            "sweep_interval_ms",
            &["999", "3600001"],
            &["1000", "3600000"],
        ),
        ("sweep_batch", &["0", "1001"], &["1", "1000"]),
        ("index_cache_bytes", &["1048575", over], &[max]),
        ("block_cache_bytes", &[over], &["0", max]),
        (
            "max_connection_age_ms",
            &["999", "86400001"],
            &["1000", "86400000"],
        ),
        (
            "max_requests_per_connection",
            &["0", "1000001"],
            &["1", "1000000"],
        ),
        ("max_connections_per_client", &["0", "33"], &["1", "32"]),
    ] {
        for v in refused {
            for r in both(key, v) {
                assert!(r.is_err(), "{key} = {v} accepted");
            }
            let e = load(&[], &[(&key.to_ascii_uppercase(), v)]).unwrap_err();
            assert!(e.to_string().contains(key), "{key} = {v}: {e}");
        }
        for v in accepted {
            for r in both(key, v) {
                assert!(r.is_ok(), "{key} = {v}: {}", r.unwrap_err());
            }
        }
    }
}

/// ADR 0019 rules 6 and 7: 0 disables eviction by age.
#[test]
fn block_ttl_zero_disables_eviction() {
    assert_eq!(
        load(&[], &[("BLOCK_TTL_MS", "0")]).unwrap().block_ttl_ms,
        None
    );
    assert_eq!(
        load(&[], &[("BLOCK_TTL_MS", "60000")])
            .unwrap()
            .block_ttl_ms,
        Some(60_000)
    );
}

/// ADR 0019 rule 37 and its open-file figures. The memory bound is the row "with the log queue,
/// `/metrics` off" of ADR 0027 clarification T1 (limiter entry 192 bytes; per-client tables and
/// pins 4 × `max_connections` × 64 bytes; log queue 262,144 bytes, ADR 0021 rule 45), plus the
/// demand set of ADR 0046 rule 25 as laid out (`2 × demand_touch_max` slots of 32 bytes, rounded
/// up to a power of two, and one flush chunk of 32,768 bytes): 1,081,344 bytes on `small`, plus
/// the network group table of ADR 0049 rule 15 (`ingest_group_max × 160 + 64`): 163,904 bytes on
/// `small`, 2,621,504 on `standard`, 20,971,584 on `large`. The `small` bound stays under 15 MB. The log bound is the figure of ADR 0021 rule 23.
#[test]
fn profiles_set_exactly_the_adr_values() {
    for (name, profile, memory, files, blocking, log_bound) in [
        ("small", Profile::Small, 14_910_996, 72, 10, 90_071_040),
        (
            "standard",
            Profile::Standard,
            112_015_248,
            312,
            26,
            444_149_760,
        ),
        (
            "large",
            Profile::Large,
            1_312_345_824,
            4_176,
            50,
            1_771_560_960,
        ),
    ] {
        let s = load(&[], &[("PROFILE", name)]).unwrap();
        assert_eq!(s.profile, profile);
        assert_eq!(s.memory_bound_bytes(), memory, "{name}");
        assert_eq!(s.log_bound_bytes_per_day(), log_bound, "{name}");
        assert_eq!(s.open_files_needed(), files, "{name}");
        assert_eq!(s.max_blocking_threads, blocking, "{name}");
        assert_eq!(s.source("profile"), Some(Source::Env));
        assert_eq!(s.source("max_connections"), Some(Source::Profile));
        // Rule 38: not set by a profile.
        assert_eq!(s.max_store_bytes, 1 << 30);
        assert_eq!(s.source("max_store_bytes"), Some(Source::Default));
        assert_eq!(s.index_max_readers, 2);
        assert_eq!(s.idle_timeout_ms, 30_000);
        assert_eq!(s.max_connection_age_ms, 300_000);
    }
}

/// ADR 0018 clarification M5: `rate_limit_max_clients >= 2 × max_connections` on the effective
/// values, from every source; the refusal names both settings and their values. The built-in
/// defaults and the three profiles satisfy it.
#[test]
fn limiter_table_must_hold_twice_the_connections() {
    for (pairs, values) in [
        (
            &[("MAX_CONNECTIONS", "2049")][..],
            "rate_limit_max_clients (4096) must be at least 2 x max_connections (2049 x 2 = 4098)",
        ),
        (
            &[("RATE_LIMIT_MAX_CLIENTS", "63"), ("MAX_CONNECTIONS", "32")][..],
            "",
        ),
        (
            &[("RATE_LIMIT_MAX_CLIENTS", "64"), ("MAX_CONNECTIONS", "33")][..],
            "rate_limit_max_clients (64) must be at least 2 x max_connections (33 x 2 = 66)",
        ),
        (
            &[("PROFILE", "standard"), ("RATE_LIMIT_MAX_CLIENTS", "511")][..],
            "rate_limit_max_clients (511) must be at least 2 x max_connections (256 x 2 = 512)",
        ),
        (
            &[("PROFILE", "large"), ("RATE_LIMIT_MAX_CLIENTS", "8191")][..],
            "rate_limit_max_clients (8191) must be at least 2 x max_connections (4096 x 2 = 8192)",
        ),
    ] {
        let e = err(&[], pairs);
        if values.is_empty() {
            // 63 is below the range of `rate_limit_max_clients`: the range check comes first.
            assert!(
                matches!(
                    &e,
                    ConfigError::OutOfRange {
                        setting: "rate_limit_max_clients",
                        ..
                    }
                ),
                "{e}"
            );
        } else {
            assert!(
                matches!(&e, ConfigError::Constraint(m) if m == values),
                "{pairs:?}: {e}"
            );
        }
    }
    // From the file too, and the environment can repair a file value.
    let f = file(
        "m5",
        "max_connections = 100\nrate_limit_max_clients = 199\n",
    );
    assert!(matches!(
        err(&["--config", &f], &[]),
        ConfigError::Constraint(m) if m.contains("rate_limit_max_clients (199)")
    ));
    assert!(load(&["--config", &f], &[("RATE_LIMIT_MAX_CLIENTS", "200")]).is_ok());
    // Exactly twice holds, at both ends of the range of `rate_limit_max_clients`.
    assert!(
        load(
            &[],
            &[("RATE_LIMIT_MAX_CLIENTS", "64"), ("MAX_CONNECTIONS", "32")]
        )
        .is_ok()
    );
    let top = load(
        &[],
        &[
            ("MAX_CONNECTIONS", "65535"),
            ("MAX_CONNECTIONS_PER_CLIENT", "8"),
            ("RATE_LIMIT_MAX_CLIENTS", "131070"),
        ],
    );
    assert!(
        !matches!(&top, Err(ConfigError::Constraint(m)) if m.contains("rate_limit_max_clients")),
        "{top:?}"
    );
    // The built-in defaults and the three profiles pass (4,096 >= 64; 32,768 >= 512;
    // 262,144 >= 8,192).
    let s = load(&[], &[]).unwrap();
    assert!(s.rate_limit_max_clients >= 2 * s.max_connections);
    for (name, clients, connections) in [
        ("small", 4_096, 32),
        ("standard", 32_768, 256),
        ("large", 262_144, 4_096),
    ] {
        let s = load(&[], &[("PROFILE", name)]).unwrap();
        assert_eq!(
            (s.rate_limit_max_clients, s.max_connections),
            (clients, connections),
            "{name}"
        );
        assert!(s.rate_limit_max_clients >= 2 * s.max_connections, "{name}");
    }
}

/// ADR 0019 rule 37, value by value; no `profile` gives the `small` column.
#[test]
fn profile_value_tables() {
    let values = |s: &Settings| {
        [
            s.max_connections,
            s.max_connections_per_client,
            s.index_max_queue,
            s.block_max_readers,
            s.block_max_queue,
            s.put_max_in_flight,
            s.put_max_queue,
            s.put_max_in_flight_per_client,
            s.rate_block_per_min,
            s.rate_block_burst,
            s.rate_query_per_min,
            s.rate_query_burst,
            s.rate_put_per_min,
            s.rate_put_burst,
            s.rate_limit_max_clients,
            s.block_cache_bytes,
            s.index_cache_bytes,
            s.log_rate_per_min,
            s.log_burst,
        ]
    };
    let none = Settings::load(Vec::<OsString>::new(), Vec::new()).unwrap();
    assert_eq!(none.profile, Profile::Small);
    assert_eq!(none.source("profile"), Some(Source::Default));
    let small = [
        32,
        8,
        32,
        4,
        32,
        4,
        16,
        2,
        3_000,
        200,
        300,
        20,
        30,
        20,
        4_096,
        2 << 20,
        4 << 20,
        60,
        120,
    ];
    assert_eq!(values(&none), small);
    let standard = load(&[], &[("PROFILE", "standard")]).unwrap();
    assert_eq!(
        values(&standard),
        [
            256,
            16,
            128,
            8,
            128,
            16,
            64,
            4,
            6_000,
            400,
            600,
            40,
            120,
            60,
            32_768,
            32 << 20,
            32 << 20,
            300,
            300
        ]
    );
    let large = load(&[], &[("PROFILE", "large")]).unwrap();
    assert_eq!(
        values(&large),
        [
            4_096,
            32,
            256,
            16,
            256,
            32,
            128,
            8,
            12_000,
            600,
            1_200,
            60,
            600,
            300,
            262_144,
            512 << 20,
            256 << 20,
            1_200,
            600
        ]
    );
}

/// ADR 0019 rule 36: default < profile < file < environment, per setting, with the source of each.
#[test]
fn profile_precedence_and_per_setting_override() {
    let path = file(
        "profile",
        "profile = \"large\"\nmax_connections = 1000\nrate_put_per_min = 100\n",
    );
    let s = load(&["--config", &path], &[]).unwrap();
    assert_eq!(s.profile, Profile::Large);
    assert_eq!(s.source("profile"), Some(Source::File));
    assert_eq!(
        (s.max_connections, s.source("max_connections")),
        (1_000, Some(Source::File))
    );
    assert_eq!(s.rate_put_per_min, 100);
    assert_eq!(
        (s.rate_put_burst, s.source("rate_put_burst")),
        (300, Some(Source::Profile))
    );
    assert_eq!(
        s.max_blocking_threads, 50,
        "computed from the effective values"
    );

    let s = load(
        &["--config", &path],
        &[("PROFILE", "standard"), ("MAX_CONNECTIONS", "500")],
    )
    .unwrap();
    assert_eq!(
        (s.profile, s.source("profile")),
        (Profile::Standard, Some(Source::Env))
    );
    assert_eq!(
        (s.max_connections, s.source("max_connections")),
        (500, Some(Source::Env))
    );
    assert_eq!(
        (s.rate_put_per_min, s.source("rate_put_per_min")),
        (100, Some(Source::File))
    );
    assert_eq!(
        (s.put_max_queue, s.source("put_max_queue")),
        (64, Some(Source::Profile))
    );
    assert_eq!(s.source("idle_timeout_ms"), Some(Source::Default));
    let lines: Vec<String> = s
        .effective_values()
        .map(|(n, v, src)| format!("{n} = {v} ({src})"))
        .collect();
    assert!(lines.contains(&"max_connections = 500 (env)".to_owned()));
    assert!(lines.contains(&"profile = standard (env)".to_owned()));
    assert!(lines.contains(&"listen = 127.0.0.1:8080 (default)".to_owned()));
    assert_eq!(lines.len(), 60, "one line per setting");

    // An override that breaks a constraint with a profile value stops the start-up and names
    // both settings; nothing is adjusted.
    let e = err(&[], &[("PROFILE", "standard"), ("MAX_CONNECTIONS", "10")]);
    assert!(
        matches!(&e, ConfigError::Constraint(m)
            if m.contains("max_connections_per_client") && m.contains("max_connections")),
        "{e}"
    );
    let e = err(&[], &[("PROFILE", "large"), ("PUT_MAX_IN_FLIGHT", "4")]);
    assert!(
        matches!(&e, ConfigError::Constraint(m) if m.contains("put_max_in_flight")),
        "{e}"
    );

    for bad in [
        file("profile-bad", "profile = \"huge\"\n"),
        file("profile-int", "profile = 3\n"),
    ] {
        assert!(matches!(
            err(&["--config", &bad], &[]),
            ConfigError::Invalid {
                setting: "profile",
                ..
            }
        ));
    }
    assert!(matches!(
        err(&[], &[("PROFILE", "Small")]),
        ConfigError::Invalid {
            setting: "profile",
            ..
        }
    ));
}

/// ADR 0020 rules 13 and 19: a prefix of 0 in `trusted_proxies`, and an IPv4-mapped block in
/// either list, stop the start-up before the index, with a message that gives the fix.
#[test]
fn trust_bounds_refuse_start() {
    for (key, setting, value, needle) in [
        (
            "TRUSTED_PROXIES",
            "trusted_proxies",
            "0.0.0.0/0",
            "prefix of 0",
        ),
        (
            "TRUSTED_PROXIES",
            "trusted_proxies",
            "127.0.0.1/32, ::/0",
            "prefix of 0",
        ),
        (
            "TRUSTED_PROXIES",
            "trusted_proxies",
            "::ffff:10.0.0.0/104",
            "`10.0.0.0/8`",
        ),
        (
            "RATE_LIMIT_EXEMPT",
            "rate_limit_exempt",
            "::ffff:192.0.2.0/120",
            "`192.0.2.0/24`",
        ),
    ] {
        let data = tmp_dir("trust-bounds");
        let e = env(&[
            ("MIN_POW_DIFFICULTY", "16"),
            (key, value),
            ("DATA_DIR", data.to_str().unwrap()),
        ]);
        let mut listened = false;
        let r = sbtp_relay::run(
            sbtp_core::self_test,
            Vec::<OsString>::new(),
            e,
            || Ok(tokio::sync::mpsc::unbounded_channel::<()>().1),
            |_| listened = true,
        );
        let Err(StartError::Config(ConfigError::Invalid { setting: s, reason })) = r else {
            panic!("{key} = {value}: {r:?}");
        };
        assert_eq!(s, setting, "{value}");
        assert!(reason.contains(needle), "{reason}");
        assert!(!listened);
        assert!(!data.exists());
    }
    // A prefix of 0 is accepted in `rate_limit_exempt`, with a warning (rule 15).
    let s = load(&[], &[("RATE_LIMIT_EXEMPT", "0.0.0.0/0")]).unwrap();
    assert!(
        warnings(&s)
            .iter()
            .any(|w| w.contains("rate_limit_exempt block 0.0.0.0/0")),
        "{:?}",
        warnings(&s)
    );
}

/// ADR 0020 rules 14 to 16 and 18: the start-up warnings and the loopback line.
#[test]
fn trust_and_bound_warnings() {
    let s = load(&[], &[]).unwrap();
    assert_eq!(warnings(&s), Vec::<String>::new());
    assert_eq!(notes(&s).len(), 1, "loopback is trusted by default");
    assert!(notes(&s)[0].contains("trusted_proxies = []"));
    let s = load(&[], &[("TRUSTED_PROXIES", "")]).unwrap();
    assert_eq!(notes(&s), Vec::<String>::new());
    let s = load(&[], &[("TRUSTED_PROXIES", "127.0.0.0/8")]).unwrap();
    assert_eq!(notes(&s).len(), 1);

    let warns = |pairs: &[(&str, &str)], needle: &str| {
        let w = warnings(&load(&[], pairs).unwrap());
        w.iter().filter(|w| w.contains(needle)).count()
    };
    // Rule 14: below /16 (IPv4) or /32 (IPv6), one warning per block.
    let wide = [(
        "TRUSTED_PROXIES",
        "10.0.0.0/8, 172.16.0.0/16, 2001:d00::/24, 2001:db8::/32",
    )];
    assert_eq!(warns(&wide, "trusted_proxies block"), 2);
    assert_eq!(warns(&wide, "10.0.0.0/8"), 1);
    assert_eq!(warns(&wide, "2001:d00::/24"), 1);
    // Rule 15: a broad exempt block; a trusted block that shares addresses with an exempt one.
    let both = [
        ("TRUSTED_PROXIES", "10.1.0.0/16, ::1/128"),
        ("RATE_LIMIT_EXEMPT", "10.1.2.0/24, 2001::/16"),
    ];
    assert_eq!(warns(&both, "block 2001::/16 is wider"), 1);
    assert_eq!(warns(&both, "share addresses"), 1);
    assert_eq!(
        warns(&both, "10.1.0.0/16 and rate_limit_exempt block 10.1.2.0/24"),
        1
    );
    // Rule 18: more than half of the slots for one key, with the source of each value.
    let half = [
        ("MAX_CONNECTIONS", "16"),
        ("MAX_CONNECTIONS_PER_CLIENT", "8"),
    ];
    assert_eq!(warns(&half, "more than half"), 0);
    assert_eq!(
        warns(
            &[("MAX_CONNECTIONS", "15")],
            "max_connections_per_client = 8 (profile) is more than half of max_connections = 15 \
             (env)"
        ),
        1
    );
    for profile in ["small", "standard", "large"] {
        assert_eq!(
            warns(&[("PROFILE", profile)], "more than half"),
            0,
            "{profile}"
        );
    }
}

/// ADR 0021 rule 46: the logging settings, their defaults, ranges and values, and the warnings of
/// rules 13 and 14.
#[test]
fn logging_settings() {
    use sbtp_relay::log::{ClientTag, Format, Level, Timestamp};
    let s = load(&[], &[]).unwrap();
    assert_eq!(
        (s.log_format, s.log_level, s.log_timestamp, s.log_client_tag),
        (
            Format::Text,
            Level::Info,
            Timestamp::Rfc3339,
            ClientTag::Off
        )
    );
    assert_eq!((s.log_rate_per_min, s.log_burst), (60, 120));
    assert_eq!(s.stats_interval_ms, 300_000);
    let s = load(
        &[],
        &[
            ("LOG_FORMAT", "json"),
            ("LOG_LEVEL", "debug"),
            ("LOG_TIMESTAMP", "none"),
            ("LOG_CLIENT_TAG", "keyed"),
            ("LOG_RATE_PER_MIN", "6000"),
            ("LOG_BURST", "16"),
            ("STATS_INTERVAL_MS", "0"),
            ("PROFILE", "large"),
        ],
    )
    .unwrap();
    assert_eq!(
        (s.log_format, s.log_level, s.log_timestamp, s.log_client_tag),
        (
            Format::Json,
            Level::Debug,
            Timestamp::None,
            ClientTag::Keyed
        )
    );
    assert_eq!(
        (s.log_rate_per_min, s.log_burst, s.stats_interval_ms),
        (6_000, 16, 0)
    );
    assert_eq!(s.source("log_burst"), Some(Source::Env));
    let codes: Vec<&str> = s.config_warnings().iter().map(|w| w.code).collect();
    assert!(codes.contains(&"debug_level") && codes.contains(&"client_tag_keyed"));
    for (key, value) in [
        ("LOG_FORMAT", "JSON"),
        ("LOG_LEVEL", "trace"),
        ("LOG_TIMESTAMP", "local"),
        ("LOG_CLIENT_TAG", "ip"),
        ("LOG_RATE_PER_MIN", "5"),
        ("LOG_RATE_PER_MIN", "6001"),
        ("LOG_BURST", "15"),
        ("LOG_BURST", "3001"),
        ("STATS_INTERVAL_MS", "9999"),
        ("STATS_INTERVAL_MS", "86400001"),
    ] {
        let e = load(&[], &[(key, value)]).unwrap_err();
        assert!(
            e.to_string().contains(&key.to_ascii_lowercase()),
            "{key} = {value}: {e}"
        );
    }

    // Security review L-3: `log_format` read alone, before the settings.
    let dir = tmp_dir("early-format");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("relay.toml");
    std::fs::write(&file, "log_format = \"json\"\n").unwrap();
    let args = [OsString::from("--config"), file.clone().into()];
    assert_eq!(sbtp_relay::config::early_log_format(&[], &[]), Format::Text);
    assert_eq!(
        sbtp_relay::config::early_log_format(&args, &[]),
        Format::Json
    );
    assert_eq!(
        sbtp_relay::config::early_log_format(&[], &env(&[("CONFIG", file.to_str().unwrap())])),
        Format::Json
    );
    assert_eq!(
        sbtp_relay::config::early_log_format(&args, &env(&[("LOG_FORMAT", "text")])),
        Format::Text
    );
    assert_eq!(
        sbtp_relay::config::early_log_format(&[], &env(&[("LOG_FORMAT", "yaml")])),
        Format::Text
    );
    assert_eq!(
        sbtp_relay::config::early_log_format(
            &[OsString::from("--config"), dir.join("none").into()],
            &[]
        ),
        Format::Text
    );
}

/// ADR 0046 rule 24: the demand settings, their ranges from both sources, the low < high
/// constraint (checked with demand eviction off too), the boolean, and the profile row of
/// `demand_touch_max`.
#[test]
fn demand_settings_and_network_difficulty() {
    for (key, refused, accepted) in [
        (
            "demand_high_water_pct",
            &["49", "100"][..],
            &["81", "99"][..],
        ),
        ("demand_low_water_pct", &["9", "99"][..], &["10", "49"][..]),
        (
            "demand_epoch_ms",
            &["14399999", "2592000001"][..],
            &["14400000", "2592000000"][..],
        ),
        (
            "demand_touch_max",
            &["1023", "16777217"][..],
            &["1024", "16777216"][..],
        ),
    ] {
        for v in refused {
            for r in both(key, v) {
                assert!(r.is_err(), "{key} = {v} accepted");
            }
        }
        for v in accepted {
            for r in both(key, v) {
                assert!(r.is_ok(), "{key} = {v}: {}", r.unwrap_err());
            }
        }
    }
    for pairs in [
        &[("DEMAND_LOW_WATER_PCT", "90")][..],
        &[
            ("DEMAND_HIGH_WATER_PCT", "60"),
            ("DEMAND_LOW_WATER_PCT", "70"),
        ][..],
        &[
            ("DEMAND_EVICTION", "false"),
            ("DEMAND_HIGH_WATER_PCT", "60"),
            ("DEMAND_LOW_WATER_PCT", "60"),
        ][..],
    ] {
        let e = err(&[], pairs);
        assert!(
            matches!(&e, ConfigError::Constraint(m)
                if m.contains("demand_low_water_pct") && m.contains("demand_high_water_pct")),
            "{e}"
        );
    }
    // The boolean: `true` or `false` in the environment, a TOML boolean in the file.
    assert!(
        !load(&[], &[("DEMAND_EVICTION", "false")])
            .unwrap()
            .demand_eviction
    );
    assert!(
        load(&[], &[("DEMAND_EVICTION", "true")])
            .unwrap()
            .demand_eviction
    );
    for bad in ["1", "yes", "False", ""] {
        let e = err(&[], &[("DEMAND_EVICTION", bad)]);
        assert!(e.to_string().contains("demand_eviction"), "{bad}: {e}");
    }
    let path = file("demand-bool", "demand_eviction = false\n");
    let s = load(&["--config", &path], &[]).unwrap();
    assert!(!s.demand_eviction);
    assert_eq!(s.source("demand_eviction"), Some(Source::File));
    let path = file("demand-str", "demand_eviction = \"false\"\n");
    assert!(load(&["--config", &path], &[]).is_err());
    // Rule 24: `demand_touch_max` is a profile row; the policy settings are not.
    for (name, touch) in [
        ("small", 16_384),
        ("standard", 131_072),
        ("large", 1_048_576),
    ] {
        let s = load(&[], &[("PROFILE", name)]).unwrap();
        assert_eq!(s.demand_touch_max, touch, "{name}");
        assert_eq!(
            (
                s.demand_high_water_pct,
                s.demand_epoch_ms,
                s.demand_eviction
            ),
            (90, 86_400_000, true)
        );
    }
    // Off: the demand set is not allocated, so not in the memory bound.
    let on = load(&[], &[]).unwrap().memory_bound_bytes();
    let off = load(&[], &[("DEMAND_EVICTION", "false")])
        .unwrap()
        .memory_bound_bytes();
    assert_eq!(on - off, 1_081_344);
}

/// ADR 0045 rules 2 and 3: the default is `D_NET`; a difficulty above it warns.
#[test]
fn difficulty_above_the_network_value_warns() {
    // ADR 0045 rule 3.
    let above = |d: &str| {
        warnings(&load(&[], &[("MIN_POW_DIFFICULTY", d)]).unwrap())
            .iter()
            .any(|w| w.contains("outside the network difficulty"))
    };
    assert!(above("17"));
    assert!(!above("16"));
    assert!(!above("12"));
    assert_eq!(
        Settings::load(Vec::<OsString>::new(), Vec::new())
            .unwrap()
            .min_pow_difficulty,
        sbtp_core::NETWORK_POW_DIFFICULTY
    );
}

/// The memory targets of the `small` profile, as CI gates (ADR 0048 budgets; ADR 0018 rule 35):
/// the computed worst case of the default settings stays under 15,000,000 bytes, and with every
/// optional function enabled under 20,000,000 bytes.
#[test]
fn small_profile_memory_bound_is_under_15_mb() {
    let s = Settings::load(Vec::<OsString>::new(), Vec::new()).unwrap();
    assert_eq!(s.profile, Profile::Small);
    assert!(
        s.memory_bound_bytes() < 15_000_000,
        "{}",
        s.memory_bound_bytes()
    );
}

/// Environment pairs (`SBTP_RELAY_` left out).
type Pairs = &'static [(&'static str, &'static str)];

/// The settings that turn on each optional function of the relay at its `small` defaults, and
/// the share of the memory bound each one adds over the same settings with it off. A new function
/// (replication of ADR 0048, the object storage mirror of ADR 0050...) adds its row here; the sum
/// of all of them stays under the "every function enabled" budget of ADR 0048.
const FUNCTIONS: &[(&str, Pairs, Pairs, u64)] = &[
    // ADR 0046 rule 25: the demand set and one flush chunk.
    (
        "demand eviction",
        &[("DEMAND_EVICTION", "true")],
        &[("DEMAND_EVICTION", "false")],
        1_081_344,
    ),
    // ADR 0049 rule 15: the network group table and the global bucket.
    (
        "ingest bounds",
        &[],
        &[("INGEST_BYTES_PER_HOUR", "0")],
        163_904,
    ),
];

/// ADR 0048 budget: `small` with every function of [`FUNCTIONS`] on stays under 20,000,000 bytes,
/// and each function adds exactly its stated share.
#[test]
fn small_profile_with_every_function_is_under_20_mb() {
    let on: Vec<(&str, &str)> = FUNCTIONS
        .iter()
        .flat_map(|(_, on, _, _)| on.iter().copied())
        .collect();
    let all = load(&[], &on).unwrap().memory_bound_bytes();
    assert!(all < 20_000_000, "{all}");
    for (name, _, off, share) in FUNCTIONS {
        let mut without = on.clone();
        without.extend_from_slice(off);
        let without = load(&[], &without).unwrap().memory_bound_bytes();
        assert_eq!(all - without, *share, "{name}");
    }
}

/// ADR 0049 rule 14: the ingest settings, their profile rows, ranges from both sources, the
/// "0 or at least 1 MiB" rule of `ingest_bytes_per_hour` and the `/56 ≤ /48` share constraint.
#[test]
fn ingest_settings() {
    for (name, r, groups) in [
        ("small", 209_715_200, 1_024),
        ("standard", 2_147_483_648, 16_384),
        ("large", 17_179_869_184, 131_072),
    ] {
        let s = load(&[], &[("PROFILE", name)]).unwrap();
        assert_eq!(
            (s.ingest_bytes_per_hour, s.ingest_group_max),
            (r, groups),
            "{name}"
        );
        // Policy settings: the same in every profile, not set by it.
        assert_eq!(
            (s.ingest_group_share_pct, s.ingest_group56_share_pct),
            (25, 10)
        );
        assert_eq!(s.source("ingest_group_share_pct"), Some(Source::Default));
    }
    for (key, refused, accepted) in [
        (
            "ingest_bytes_per_hour",
            &["1", "1048575", "1099511627777"][..],
            &["0", "1048576", "1099511627776"][..],
        ),
        (
            "ingest_group_max",
            &["63", "16777217"][..],
            &["64", "16777216"][..],
        ),
        (
            "ingest_group_share_pct",
            &["0", "101"][..],
            &["10", "100"][..],
        ),
        (
            "ingest_group56_share_pct",
            &["0", "26"][..],
            &["1", "25"][..],
        ),
    ] {
        for v in refused {
            for r in both(key, v) {
                assert!(r.is_err(), "{key} = {v} accepted");
            }
        }
        for v in accepted {
            for r in both(key, v) {
                assert!(r.is_ok(), "{key} = {v}: {}", r.unwrap_err());
            }
        }
    }
    let e = err(
        &[],
        &[
            ("INGEST_GROUP_SHARE_PCT", "20"),
            ("INGEST_GROUP56_SHARE_PCT", "21"),
        ],
    );
    assert!(
        matches!(&e, ConfigError::Constraint(m)
            if m.contains("ingest_group56_share_pct") && m.contains("ingest_group_share_pct")),
        "{e}"
    );
}
