//! SBTP dumb relay library. Specification: `docs/spec/sbtp-core-v0.2.md` §4 and
//! `docs/spec/architecture.md` §2.
//!
//! Status: Phase 2, relay milestone 1c-b: settings, start-up order, accept loop with the connection
//! bounds of ADR 0018, error mapping, `GET /sbtp/v1/info` and CORS; logger and counters of ADR 0021;
//! block store (one shard level, ADR 0025), `PUT /sbtp/v1/block`, `GET /sbtp/v1/block/{block_id}`
//! and `GET /sbtp/v1/query` with index epochs (ADR 0024); dedicated index threads (ADR 0018 rules
//! 9 to 13) and the `query` token bucket (rule 21).
//!
//! Nothing writes to standard output or standard error outside [`log`] (ADR 0021 rule 1); the two
//! lints below keep `print!`-style macros out.
#![deny(clippy::print_stdout, clippy::print_stderr)]
// TODO(1c): `block` and `put` token buckets, eviction, disk watermark, `/metrics`.

pub mod api;
pub mod blocks;
pub mod cache;
pub mod client;
pub mod config;
pub mod error;
pub mod index;
pub mod limiter;
pub mod log;
pub mod metrics;
pub mod pool;
pub mod query;
pub mod server;
pub mod store;

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
    let settings = Settings::load(args, env).map_err(StartError::Config)?;
    if settings.log_client_tag == log::ClientTag::Keyed {
        log::client_tag_key().map_err(|e| StartError::Io("drawing the client tag key", e))?;
    }
    log::global().configure(&LogConfig::from_settings(&settings));
    log_settings(&settings)?;

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
    let index = Arc::new(RedbIndex::open(&index_file, cache)?);
    // ADR 0018 rules 9 to 11: from here on only the index threads call the index.
    let pool = IndexPool::start(&index, &settings)
        .map_err(|e| StartError::Io("starting the index threads", e))?;
    let opened = Store::open(&data_dir, index_file, settings.max_store_bytes)
        .map_err(|e| StartError::Io("opening the block store", e))
        .and_then(|store| {
            // ADR 0023 rule 15, before listening: the index is ready when the relay listens
            // (rule 11). The walk is one job of the writer thread: its lookups and inserts run
            // there, before any request can queue a read.
            let walked = pool
                .handle()
                .write_blocking(move |i| {
                    let r = store::reconcile(&store, i).map(|_| ());
                    (store, r)
                })
                .map_err(|_| StartError::Shutdown("the index writer thread is not running"))?;
            match walked {
                (store, Ok(())) => Ok(store),
                (_, Err(ReconcileError::Io(e))) => {
                    Err(StartError::Io("reconciling the block store", e))
                }
                (_, Err(ReconcileError::Index(e))) => Err(StartError::Index(e)),
            }
        });
    let served = match opened {
        Ok(store) => {
            let app = api::app(
                &settings,
                Arc::new(Relay::new(&settings, store, pool.handle())),
            );
            serve(&settings, app, shutdown, on_listen)
        }
        Err(e) => Err(e),
    };
    // Every exit path after the index is open. The first error wins; the later steps still run.
    let durable = pool.shutdown().map_err(|e| match e {
        ShutdownError::Flush(e) => StartError::Index(e),
        ShutdownError::Panicked(m) => StartError::Shutdown(m),
    });
    let closed = Arc::try_unwrap(index)
        .map_err(|_| StartError::Shutdown("index still shared, not closed"))
        .and_then(|i| i.close().map_err(StartError::Index));
    if closed.is_ok() {
        log::emit(Event::Shutdown, &[("phase", Value::Str("index_closed"))]);
    }
    served.and(durable).and(closed)
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
/// installs the shutdown signal, binds and serves.
fn serve<S, T>(
    settings: &Settings,
    app: axum::Router,
    shutdown: S,
    on_listen: impl FnOnce(SocketAddr),
) -> Result<(), StartError>
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
        server::serve(listener, app, limits, shutdown)
            .await
            .map_err(|e| StartError::Io("serving", e))
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
