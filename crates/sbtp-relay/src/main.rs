//! The relay binary: configuration from the environment, logs to stderr, stops on SIGINT or
//! SIGTERM.

use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // PRINCIPLES "Relay scope": one line per event on stderr, never a payload, key or client IP.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .init();
    let config = sbtp_relay::Config::from_env().map_err(|name| format!("{name}: invalid value"))?;
    // Loopback by default: public exposure goes through a TLS reverse proxy.
    let listen = std::env::var("SBTP_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(listen, "listening");
    let mut term = signal(SignalKind::terminate())?;
    let shutdown = async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    sbtp_relay::run(listener, config, shutdown).await
}
