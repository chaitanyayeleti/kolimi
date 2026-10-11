//! `kolimi-sync` — one-shot bidirectional sync between a local directory
//! and a Kolimi server (desktop client core alpha).

use std::error::Error;
use std::path::PathBuf;

use clap::Parser;
use kolimi_sync::{SyncConfig, sync_once};

#[derive(Parser)]
#[command(
    name = "kolimi-sync",
    version,
    about = "Sync a local directory with a Kolimi server (delta protocol)"
)]
struct Cli {
    /// Server base URL, e.g. https://cloud.example.com
    #[arg(long, env = "KOLIMI_SERVER")]
    server: String,

    /// Username (HTTP Basic).
    #[arg(long, env = "KOLIMI_USER")]
    user: String,

    /// Password (HTTP Basic).
    #[arg(long, env = "KOLIMI_PASSWORD")]
    password: String,

    /// Local directory to mirror.
    #[arg(long)]
    local: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = SyncConfig {
        server: cli.server,
        username: cli.user,
        password: cli.password,
        local_dir: cli.local,
    };
    let report = sync_once(&config).await?;
    println!(
        "sync complete: pulled {}, pushed {}, removed locally {}, removed remotely {}, conflicts {}",
        report.pulled, report.pushed, report.removed_local, report.removed_remote, report.conflicts
    );
    Ok(())
}
