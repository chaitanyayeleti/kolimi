//! Kolimi server — a pure-Rust, single-binary alternative to Nextcloud.
//!
//! M0 skeleton: exposes the process lifecycle (bind, log, graceful shutdown)
//! and health endpoints. WebDAV, auth, and the storage engine land in M1/M2.

use std::net::SocketAddr;

use axum::{Json, Router, routing::get};
use clap::Parser;
use serde_json::{Value, json};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "kolimi-server",
    version,
    about = "Kolimi server — a pure-Rust, single-binary alternative to Nextcloud"
)]
struct Args {
    /// Address to bind the HTTP listener to.
    #[arg(long, env = "KOLIMI_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version));

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(bind = %args.bind, "kolimi server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("kolimi server stopped");
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn version() -> Json<Value> {
    Json(json!({
        "name": "kolimi-server",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(_) => std::future::pending().await,
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
