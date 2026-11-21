//! SBTP dumb relay library. Specification: `docs/spec/sbtp-core-v0.2.md` §4 and
//! `docs/spec/architecture.md` §2.
//!
//! Status: Phase 2, relay milestone 1c-b: settings, start-up order, accept loop with the connection
//! bounds of ADR 0018, error mapping, `GET /sbtp/v1/info` and CORS; logger and counters of ADR 0021;
//! block store (one shard level, ADR 0025), `PUT /sbtp/v1/block`, `GET /sbtp/v1/block/{block_id}`
//! and `GET /sbtp/v1/query` with index epochs (ADR 0024); dedicated index threads (ADR 0018 rules
//! 9 to 13) and the `query` token bucket (rule 21); the age-based sweeper ([`sweep`], ADR 0013
//! rule 15) and the re-acceptance of expired blocks (ADR 0043).
//!
//! Nothing writes to standard output or standard error outside [`log`] (ADR 0021 rule 1); the two
//! lints below keep `print!`-style macros out.
#![deny(clippy::print_stdout, clippy::print_stderr)]
// TODO(1c): disk watermark, `/metrics`.

pub mod api;
pub mod batch;
pub mod blocks;
pub mod cache;
pub mod client;
pub mod config;
pub mod demand;
pub mod error;
pub mod index;
pub mod ingest;
pub mod limiter;
pub mod log;
pub mod metrics;
#[cfg(feature = "object-store")]
pub mod mirror;
pub mod peers;
pub mod pool;
pub mod query;
#[cfg(feature = "replication")]
pub mod replication;
pub mod server;
pub mod store;
pub mod sweep;

use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use blocks::Relay;
use config::{ConfigError, Settings};
use index::{IndexBackend, IndexError, RedbIndex};
use log::{Event, LogConfig, Value};
use pool::{IndexPool, ShutdownError};
use sbtp_core::SelfTestError;
use store::{ReconcileError, Store};

/// Why the relay did not start, or did not stop cleanly.
#[derive(Debug)]
pub enum StartError {
    /// ADR 0003 rule 16: the start-up self-test failed. Nothing else was done.
    SelfTest(SelfTestError),
    /// ADR 0018 rule 7: a setting is invalid. Nothing was opened.
    Config(ConfigError),
    /// An operating-system error, with what was being done.
    Io(&'static str, std::io::Error),
    /// The index failed to open, flush or close.
    Index(IndexError),
    /// Shutdown did not complete cleanly.
    Shutdown(&'static str),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfTest(e) => write!(f, "self-test failed, refusing to start: {e}"),
            Self::Config(e) => write!(f, "invalid configuration, refusing to start: {e}"),
            Self::Io(what, e) => write!(f, "{what}: {e}"),
            Self::Index(e) => write!(f, "index: {e}"),
            Self::Shutdown(m) => write!(f, "shutdown: {m}"),
        }
    }
}

impl std::error::Error for StartError {}

impl From<IndexError> for StartError {
    fn from(e: IndexError) -> Self {
        Self::Index(e)
    }
}

/// Runs the relay, in the start-up order of milestone 1: `self_test` (ADR 0003 rule 16), then the
/// settings from `args` and `env` (ADR 0018 rules 6 and 7), then the index and the block store,
/// reconciled by the one start-up walk (ADR 0013 rules 9 and 11, ADR 0023 rule 15) on the index
/// writer thread, then the runtime and the listener. `shutdown` builds, inside the runtime, the
/// [`server::StopSignal`] that stops the relay (a second signal skips the drain); `on_listen`
/// receives the bound address. After the accept loop ends: index threads stopped after a final
/// flush, index closed (security review F-3), each step run even if an earlier one failed.
///
/// # Errors
///
/// [`StartError`]; the first error wins.
#[allow(clippy::too_many_lines)] // The start-up order, in one place.
pub fn run<A, E, S, T>(
    self_test: fn() -> Result<(), SelfTestError>,
    args: A,
    env: E,
    shutdown: S,
    on_listen: impl FnOnce(SocketAddr),
) -> Result<(), StartError>
where
    A: IntoIterator<Item = OsString>,
    E: IntoIterator<Item = (OsString, OsString)>,
    S: FnOnce() -> std::io::Result<T>,
    T: server::StopSignal,
{
    // Security review L-3: `log_format` alone first, so that this line and an early `fatal`
    // line have the configured form; the other logger settings are applied once loaded.
    let args: Vec<OsString> = args.into_iter().collect();
    let env: Vec<(OsString, OsString)> = env.into_iter().collect();
    log::global().configure(&LogConfig {
        format: config::early_log_format(&args, &env),
        ..LogConfig::default()
    });
    // ADR 0019 rule 26. The version goes to the log only, never to the network (rule 25).
    log::emit(
        Event::Start,
        &[
            ("name", Value::Str(env!("CARGO_PKG_NAME"))),
            ("version", Value::Str(env!("CARGO_PKG_VERSION"))),
        ],
    );
    self_test().map_err(StartError::SelfTest)?;
    // Kept only for the credentials of ADR 0050 rule 22, then dropped.
    #[cfg(feature = "object-store")]
    let env_kept = env.clone();
    #[cfg(not(feature = "object-store"))]
    let env_kept: Vec<(OsString, OsString)> = Vec::new();
    let settings = Settings::load(args, env).map_err(StartError::Config)?;
    if settings.log_client_tag == log::ClientTag::Keyed {
        log::client_tag_key().map_err(|e| StartError::Io("drawing the client tag key", e))?;
    }
    log::global().configure(&LogConfig::from_settings(&settings));
    log_settings(&settings)?;
    // ADR 0048 rule 19: the trust roots are loaded once, before anything is opened.
    let replication = prepare_replication(&settings)?;
    // ADR 0050 rule 22: the credentials are read once, from the start-up environment.
    let mirror = prepare_mirror(&settings, &env_kept)?;
    drop(env_kept);

    // Mode `0700` for what this creates (security review L-4); an existing directory is kept.
    store::dir_builder()
        .recursive(true)
        .create(&settings.data_dir)
        .map_err(|e| StartError::Io("creating the data directory", e))?;
    let data_dir = std::fs::canonicalize(&settings.data_dir)
        .map_err(|e| StartError::Io("resolving the data directory", e))?;
    // ADR 0019 rule 10.
    let path = data_dir.display().to_string();
    log::emit(Event::DataDir, &[("path", Value::Str(&path))]);
    let cache = usize::try_from(settings.index_cache_bytes).unwrap_or(usize::MAX);
    let index_file = data_dir.join("index.redb");
    let index = RedbIndex::open(&index_file, cache)?;
    // ADR 0046 rule 13: read before anything else writes; implementation plan step 2: the demand
    // entries of an index written before ADR 0046, before any request. Security review
    // 2026-11-21: the migration and the `demand_eviction` record tell whether the index holds a
    // demand history (M-1); the suspension of the last clean close is restored (L-1).
    let mut start = demand_start(&index, &settings)?;
    let index = Arc::new(index);
    // ADR 0018 rules 9 to 11: from here on only the index threads call the index.
    let pool = IndexPool::start(&index, &settings)
        .map_err(|e| StartError::Io("starting the index threads", e))?;
    let opened = Store::open(&data_dir, index_file, settings.max_store_bytes)
        .map_err(|e| StartError::Io("opening the block store", e))
        .and_then(|store| {
            // ADR 0023 rule 15, before listening: the index is ready when the relay listens
            // (rule 11). The walk is one job of the writer thread: its lookups and inserts run
            // there, before any request can queue a read.
            // Whether the index holds a block is read after the walk, which re-indexes the files
            // of a rebuilt index with their file times: no demand history either (M-1).
            let walked = pool
                .handle()
                .write_blocking(move |i| {
                    let r = store::reconcile(&store, i)
                        .and_then(|_| i.is_empty().map_err(ReconcileError::Index));
                    (store, r)
                })
                .map_err(|_| StartError::Shutdown("the index writer thread is not running"))?;
            match walked {
                (store, Ok(empty)) => Ok((store, empty)),
                (_, Err(ReconcileError::Io(e))) => {
                    Err(StartError::Io("reconciling the block store", e))
                }
                (_, Err(ReconcileError::Index(e))) => Err(StartError::Index(e)),
            }
        });
    let served = match opened {
        Ok((store, empty)) => match Relay::new(&settings, store, pool.handle()) {
            Ok(relay) => {
                start.empty = empty;
                relay.demand().start(&start, log::unix_ms());
                let relay = Arc::new(relay);
                let kept = Arc::clone(&relay);
                let app = api::app(&settings, Arc::clone(&relay));
                let drain = serve(
                    &settings,
                    app,
                    relay,
                    (replication, mirror),
                    shutdown,
                    on_listen,
                );
                // L-1: written by the clean mark, restored at the next start.
                let until = kept.demand().suspended_until();
                drop(kept);
                drain.map(|d| (d, until))
            }
            Err(e) => Err(StartError::Io(
                "allocating the demand set",
                std::io::Error::new(std::io::ErrorKind::OutOfMemory, e),
            )),
        },
        Err(e) => Err(e),
    };
    // Every exit path after the index is open. The first error wins; the later steps still run.
    let durable = pool.shutdown().map_err(|e| match e {
        ShutdownError::Flush(e) => StartError::Index(e),
        ShutdownError::Panicked(m) => StartError::Shutdown(m),
    });
    // ADR 0046 rule 13: the index is marked closed cleanly only when every write is durable, the
    // demand set was flushed, and every request handler had ended before that flush; otherwise
    // the next start suspends demand eviction. Security review 2026-11-21, L-3: after a drain cut
    // by its deadline or a second signal, handlers still running can record a demand after the
    // final flush, which would be lost without a trace; such a stop is therefore not clean.
    let suspended_until = match &served {
        Ok((drain, until)) if drain.complete() && durable.is_ok() => Some(*until),
        _ => None,
    };
    let served = served.map(|_| ());
    let closed = Arc::try_unwrap(index)
        .map_err(|_| StartError::Shutdown("index still shared, not closed"))
        .and_then(|i| {
            let marked = if let Some(until) = suspended_until {
                i.mark_clean(until).map_err(StartError::Index)
            } else {
                Ok(())
            };
            let closed = i.close().map_err(StartError::Index);
            marked.and(closed)
        });
    if closed.is_ok() {
        log::emit(Event::Shutdown, &[("phase", Value::Str("index_closed"))]);
    }
    served.and(durable).and(closed)
}

/// The start state of demand eviction (ADR 0046 rule 13, clarifications D1 and D2), read and
/// recorded before the index is shared: the unclean mark, the stored suspension end, the
/// migration of an index written before ADR 0046, and the `demand_eviction` of the previous start
/// (this start's value is recorded, durably). `empty` is set after the start-up walk.
fn demand_start(index: &RedbIndex, settings: &Settings) -> Result<demand::StartState, IndexError> {
    Ok(demand::StartState {
        unclean: index.unclean_start(),
        suspended_until: index.suspended_until(),
        migrated: index.configure_demand(settings.demand_epoch_ms)? > 0,
        previous: index.record_demand_eviction(settings.demand_eviction)?,
        empty: false,
    })
}

/// What [`serve`] starts beside the accept loop when replication is on (ADR 0048 rule 3).
#[cfg(feature = "replication")]
type Replicator = replication::Replication;
#[cfg(not(feature = "replication"))]
type Replicator = std::convert::Infallible;

#[cfg(feature = "replication")]
fn prepare_replication(settings: &Settings) -> Result<Option<Replicator>, StartError> {
    replication::Replication::prepare(settings).map_err(StartError::Config)
}

#[cfg(not(feature = "replication"))]
#[allow(clippy::unnecessary_wraps)] // The signature of the feature build.
fn prepare_replication(_: &Settings) -> Result<Option<Replicator>, StartError> {
    Ok(None)
}

/// What [`serve`] starts beside the accept loop when the archive copy is on (ADR 0050 rule 26).
#[cfg(feature = "object-store")]
type Mirrorer = mirror::Mirror;
#[cfg(not(feature = "object-store"))]
type Mirrorer = std::convert::Infallible;

#[cfg(feature = "object-store")]
fn prepare_mirror(
    settings: &Settings,
    env: &[(OsString, OsString)],
) -> Result<Option<Mirrorer>, StartError> {
    mirror::Mirror::prepare(settings, env).map_err(StartError::Config)
}

#[cfg(not(feature = "object-store"))]
#[allow(clippy::unnecessary_wraps)] // The signature of the feature build.
fn prepare_mirror(
    _: &Settings,
    _: &[(OsString, OsString)],
) -> Result<Option<Mirrorer>, StartError> {
    Ok(None)
}

/// Starts the archive copy, when prepared; the task ends at the stop, or if it panics.
#[allow(clippy::needless_pass_by_value)] // Moved into the task in the feature build.
fn spawn_mirror(
    m: Option<Mirrorer>,
    relay: &Arc<Relay<RedbIndex>>,
    stopped: &tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    #[cfg(feature = "object-store")]
    return m.map(|m| m.spawn(Arc::clone(relay), stopped.clone()));
    #[cfg(not(feature = "object-store"))]
    {
        let _ = (relay, stopped);
        m.map(|never| match never {})
    }
}

/// Waits for `h`, or forever when there is none.
async fn ended(h: Option<&mut tokio::task::JoinHandle<()>>) {
    match h {
        Some(h) => {
            let _ = h.await;
        }
        None => std::future::pending().await,
    }
}

/// Starts replication, when prepared; the task ends at the stop, or when a worker ends.
#[allow(clippy::needless_pass_by_value)] // Moved into the task in the feature build.
fn spawn_replication(
    r: Option<Replicator>,
    relay: &Arc<Relay<RedbIndex>>,
    stopped: &tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    #[cfg(feature = "replication")]
    return r.map(|r| r.spawn(Arc::clone(relay), stopped.clone()));
    #[cfg(not(feature = "replication"))]
    {
        let _ = (relay, stopped);
        r.map(|never| match never {})
    }
}

/// The start-up lines from `profile` to `config_warning` (ADR 0019 rules 22 and 36.6, ADR 0018
/// rule 35, ADR 0021 rule 22), and the open-file check.
fn log_settings(settings: &Settings) -> Result<(), StartError> {
    let source = |name| settings.source(name).unwrap_or(config::Source::Default);
    log::emit(
        Event::Profile,
        &[
            ("name", Value::Str(settings.profile.name())),
            ("source", Value::Str(&source("profile").to_string())),
        ],
    );
    for (name, value, source) in settings.effective_values() {
        let source = source.to_string();
        let fields = [
            ("name", Value::Str(name)),
            ("value", Value::Str(&value)),
            ("source", Value::Str(&source)),
        ];
        log::emit(Event::Setting, &fields);
    }
    let needed = Value::Int(settings.open_files_needed());
    match settings.check_open_files().map_err(StartError::Config)? {
        Some(u64::MAX) => log::emit(
            Event::OpenFiles,
            &[("unlimited", Value::Bool(true)), ("needed", needed)],
        ),
        Some(limit) => log::emit(
            Event::OpenFiles,
            &[("limit", Value::Int(limit)), ("needed", needed)],
        ),
        None => log::emit(
            Event::ConfigWarning,
            &[
                ("code", Value::Str("open_files_unchecked")),
                ("setting", Value::Str("max_connections")),
                ("needed", needed),
                (
                    "msg",
                    Value::Str(
                        "the open-file limit is not checked on this target (ADR 0019 rule 22)",
                    ),
                ),
            ],
        ),
    }
    log::emit(
        Event::MemoryBound,
        &[("bytes", Value::Int(settings.memory_bound_bytes()))],
    );
    log::emit(
        Event::LogBound,
        &[(
            "bytes_per_day",
            Value::Int(settings.log_bound_bytes_per_day()),
        )],
    );
    for w in settings
        .config_notes()
        .into_iter()
        .chain(settings.config_warnings())
    {
        log::emit(
            Event::ConfigWarning,
            &[
                ("code", Value::Str(w.code)),
                ("setting", Value::Str(w.setting)),
                ("msg", Value::Str(&w.msg)),
            ],
        );
    }
    Ok(())
}

/// Builds the runtime (ADR 0018 rule 19: explicit `worker_threads` and `max_blocking_threads`),
/// installs the shutdown signal, binds and serves. The sweeper ([`sweep::run`]) runs beside the
/// accept loop; if it ends while the relay serves (a run panicked), the process exits like a
/// supervised index thread (ADR 0018 rule 37). On shutdown it is stopped and its current run, if
/// any, is waited for, before the index threads stop. Returns how the drain ended.
fn serve<S, T>(
    settings: &Settings,
    app: axum::Router,
    relay: Arc<Relay<RedbIndex>>,
    (replication, mirror): (Option<Replicator>, Option<Mirrorer>),
    shutdown: S,
    on_listen: impl FnOnce(SocketAddr),
) -> Result<server::Drain, StartError>
where
    S: FnOnce() -> std::io::Result<T>,
    T: server::StopSignal,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(usize::try_from(settings.worker_threads).unwrap_or(1))
        .max_blocking_threads(usize::try_from(settings.max_blocking_threads).unwrap_or(1))
        .enable_all()
        .build()
        .map_err(|e| StartError::Io("building the runtime", e))?;
    // ADR 0027 clarification T2: the limiter table is allocated before the relay listens; if the
    // allocation fails, the relay does not start.
    let limits = server::ConnLimits::from_settings(settings).map_err(|e| {
        StartError::Io(
            "allocating the rate-limiter table",
            std::io::Error::new(std::io::ErrorKind::OutOfMemory, e),
        )
    })?;
    runtime.block_on(async {
        // Installed before listening, so that a failure is an error, not a panic.
        let shutdown = shutdown().map_err(|e| StartError::Io("installing signal handlers", e))?;
        let listener = tokio::net::TcpListener::bind(settings.listen)
            .await
            .map_err(|e| StartError::Io("binding the listen address", e))?;
        let local = listener
            .local_addr()
            .map_err(|e| StartError::Io("reading the listen address", e))?;
        // ADR 0019 rule 9; the warning is in `config_warnings`. The relay's own address.
        let addr = local.to_string();
        log::emit(Event::Listening, &[("addr", Value::Str(&addr))]);
        on_listen(local);
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let flushed = Arc::clone(&relay);
        // ADR 0048: replication runs beside the accept loop, like the sweeper; if it ends while
        // the relay serves (a worker panicked), the process exits (ADR 0018 rule 37).
        let mut replicator = spawn_replication(replication, &relay, &stopped);
        // ADR 0050: the archive copy, likewise.
        let mut mirrorer = spawn_mirror(mirror, &relay, &stopped);
        let mut sweeper = tokio::spawn(sweep::run(
            relay,
            std::time::Duration::from_millis(settings.sweep_interval_ms),
            usize::try_from(settings.sweep_batch).unwrap_or(index::MAX_QUERY_LIMIT),
            stopped,
        ));
        let served = tokio::select! {
            r = server::serve(listener, app, limits, shutdown) => r,
            _ = &mut sweeper => {
                log::emit(Event::Fatal, &[("msg", Value::Str("the sweeper ended"))]);
                log::flush();
                std::process::exit(pool::EXIT_THREAD_ENDED);
            }
            () = ended(replicator.as_mut()) => {
                log::emit(Event::Fatal, &[("msg", Value::Str("replication ended"))]);
                log::flush();
                std::process::exit(pool::EXIT_THREAD_ENDED);
            }
            () = ended(mirrorer.as_mut()) => {
                log::emit(Event::Fatal, &[("msg", Value::Str("the archive copy ended"))]);
                log::flush();
                std::process::exit(pool::EXIT_THREAD_ENDED);
            }
        };
        let _ = stop.send(true);
        let _ = sweeper.await;
        if let Some(h) = replicator {
            let _ = h.await;
        }
        if let Some(h) = mirrorer {
            let _ = h.await;
        }
        // ADR 0046 rule 12: the last flush of the demand set, at a clean shutdown, after the
        // sweeper task (the only other flusher) has stopped.
        let lost = tokio::task::spawn_blocking(move || sweep::flush_demand(&flushed).lost)
            .await
            .unwrap_or(1);
        let drain = served.map_err(|e| StartError::Io("serving", e))?;
        if lost > 0 {
            return Err(StartError::Shutdown("the demand set was not flushed"));
        }
        Ok(drain)
    })
}

/// The stop signal of the shipped binary: `SIGTERM` or `SIGINT`. The handlers stay installed,
/// so a second signal during the drain is seen (security review F-4).
#[cfg(unix)]
pub struct Signals {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl server::StopSignal for Signals {
    async fn recv(&mut self) {
        tokio::select! {
            _ = self.terminate.recv() => {},
            _ = self.interrupt.recv() => {},
        }
    }
}

/// Installs the handlers of [`Signals`].
///
/// # Errors
///
/// A signal handler could not be installed.
#[cfg(unix)]
pub fn signals() -> std::io::Result<Signals> {
    use tokio::signal::unix::{SignalKind, signal};
    Ok(Signals {
        terminate: signal(SignalKind::terminate())?,
        interrupt: signal(SignalKind::interrupt())?,
    })
}
