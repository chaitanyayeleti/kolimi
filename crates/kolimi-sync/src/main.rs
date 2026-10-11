//! `kolimi-sync` — one-shot bidirectional sync between a local directory
//! and a Kolimi server (desktop client core alpha).

use std::error::Error;
use std::path::PathBuf;

use clap::Parser;
use kolimi_crypto::recovery_code_display;
use kolimi_sync::{E2eeOptions, SyncConfig, create_keyring, sync_once, upload_keyring};

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

    /// Generate and upload an E2EE keyring, then exit. The passphrase is
    /// read from KOLIMI_E2EE_PASSPHRASE or prompted.
    #[arg(long)]
    e2ee_setup: bool,

    /// Relative paths (repeatable / comma-separated) whose files are
    /// encrypted end-to-end (RFC 0007).
    #[arg(long = "e2ee-root", value_delimiter = ',')]
    e2ee_roots: Vec<String>,

    /// E2EE passphrase (unlock). Prefer the environment variable.
    #[arg(long, env = "KOLIMI_E2EE_PASSPHRASE", hide_env_values = true)]
    e2ee_passphrase: Option<String>,

    /// E2EE recovery code (alternative unlock path).
    #[arg(long, env = "KOLIMI_E2EE_RECOVERY", hide_env_values = true)]
    e2ee_recovery: Option<String>,

    /// WebAuthn PRF output as hex (64 chars) for passkey unlock; platform
    /// shells usually pass this via the library API instead.
    #[arg(long, env = "KOLIMI_E2EE_PRF", hide_env_values = true)]
    e2ee_prf: Option<String>,
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err("hex length must be even".to_string());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| "invalid hex digits".to_string())
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = SyncConfig {
        server: cli.server,
        username: cli.user,
        password: cli.password,
        local_dir: cli.local,
        e2ee: if cli.e2ee_roots.is_empty() {
            None
        } else {
            let prf_secret = match &cli.e2ee_prf {
                Some(hex) => Some(hex_decode(hex).map_err(|e| format!("--e2ee-prf: {e}"))?),
                None => None,
            };
            Some(E2eeOptions {
                passphrase: cli.e2ee_passphrase.clone(),
                recovery_code: cli.e2ee_recovery.clone(),
                prf_secret,
                encrypted_roots: cli.e2ee_roots.clone(),
            })
        },
    };

    if cli.e2ee_setup {
        let passphrase = match cli.e2ee_passphrase.clone() {
            Some(passphrase) => passphrase,
            None => {
                let passphrase = rpassword::prompt_password("New E2EE passphrase: ")?;
                let confirm = rpassword::prompt_password("Repeat passphrase: ")?;
                if passphrase != confirm {
                    return Err("passphrases do not match".into());
                }
                passphrase
            }
        };
        let (keyring, recovery) = create_keyring(&passphrase)?;
        upload_keyring(&config, &keyring).await?;
        println!(
            "keyring uploaded ({} unlock methods)",
            keyring.methods().len()
        );
        println!();
        println!("Recovery code (store it somewhere safe, it is shown once):");
        println!("  {}", recovery_code_display(&recovery));
        println!();
        println!("Losing the passphrase and the recovery code means the data is unrecoverable.");
        return Ok(());
    }

    let report = sync_once(&config).await?;
    println!(
        "sync complete: pulled {}, pushed {}, removed locally {}, removed remotely {}, conflicts {}",
        report.pulled, report.pushed, report.removed_local, report.removed_remote, report.conflicts
    );
    Ok(())
}
