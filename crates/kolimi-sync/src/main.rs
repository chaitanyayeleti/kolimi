//! `kolimi-sync` — one-shot bidirectional sync between a local directory
//! and a Kolimi server (desktop client core alpha).

use std::error::Error;
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use kolimi_crypto::recovery_code_display;
use kolimi_sync::{
    E2eeOptions, ShareTarget, SyncConfig, create_keyring, known_recipient_keys, publish_identity,
    share_path, sync_once_rooted, unshare_path, upload_keyring,
};

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

    /// Remote subfolder to mirror (absolute server path; default the account
    /// root). Lets several local directories sync to distinct server folders.
    #[arg(long, default_value = "/")]
    remote: String,

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

    /// Enroll this device (RFC 0008): create an enrollment and wait for an
    /// already-unlocked device to approve it, then save `.kolimi/device.json`.
    #[arg(long = "e2ee-enroll", value_name = "DEVICE_NAME")]
    e2ee_enroll: Option<String>,

    /// Approve a pending device enrollment by id, wrapping this (unlocked)
    /// device's master key for the new device (RFC 0008).
    #[arg(long = "e2ee-approve", value_name = "ENROLLMENT_ID")]
    e2ee_approve: Option<i64>,

    /// The approval code shown on the new device (with --e2ee-approve). When
    /// omitted you are prompted to type it.
    #[arg(long = "e2ee-code", value_name = "CODE")]
    e2ee_code: Option<String>,

    /// Print the recipient encryption keys pinned on this device (TOFU).
    #[arg(long = "e2ee-fingerprints")]
    e2ee_fingerprints: bool,

    /// Forget this device's local key material (the OS-keystore entry and
    /// `.kolimi/device.json`), so it must be enrolled again.
    #[arg(long = "e2ee-forget-device")]
    e2ee_forget_device: bool,

    /// Share a path (relative to --local) with a user, wrapping E2EE keys.
    #[arg(long)]
    share: Option<String>,

    /// Recipient user for --share/--unshare.
    #[arg(long)]
    with: Option<String>,

    /// Recipient group for --share/--unshare (keys wrapped per member).
    #[arg(long)]
    group: Option<String>,

    /// Revoke the share of --share from --with instead of creating one.
    #[arg(long)]
    unshare: bool,
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
        token: None,
        local_dir: cli.local,
        e2ee: if cli.e2ee_roots.is_empty() && cli.e2ee_approve.is_none() {
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

    if let Some(name) = cli.e2ee_enroll.clone() {
        let pending = kolimi_sync::start_enrollment(&config, &name).await?;
        println!("Enrollment {} created for “{name}”.", pending.details.id);
        println!("On the already-unlocked device, compare this code before approving:");
        println!("  approval code:   {}", pending.details.code);
        println!("  key fingerprint: {}", pending.details.fingerprint);
        let id = kolimi_sync::finish_enrollment(&config, &pending).await?;
        println!(
            "enrolled this device (enrollment {id}); device key saved to the OS keystore (or .kolimi/device.json)"
        );
        return Ok(());
    }

    if let Some(id) = cli.e2ee_approve {
        let pending = kolimi_sync::pending_enrollment(&config, id).await?;
        println!(
            "Pending device “{}” (enrollment {})",
            pending.name, pending.id
        );
        println!("  key fingerprint: {}", pending.fingerprint);
        println!("  approval code:   {}", pending.code);
        let code = match cli.e2ee_code.clone() {
            Some(code) => code,
            None => {
                print!("Confirm the code shown on the new device: ");
                std::io::stdout().flush()?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                line
            }
        };
        let name = kolimi_sync::approve_device(&config, id, &code).await?;
        println!("approved device “{name}” (enrollment {id})");
        return Ok(());
    }

    if cli.e2ee_fingerprints {
        let keys = known_recipient_keys(&config.local_dir)?;
        if keys.is_empty() {
            println!("no recipient keys pinned yet");
        } else {
            for (member, fingerprint) in keys {
                println!("{member}  {fingerprint}");
            }
        }
        return Ok(());
    }

    if cli.e2ee_forget_device {
        if kolimi_sync::forget_device(&config.local_dir)? {
            println!("forgot this device's local key material");
        } else {
            println!("this device had no local key material");
        }
        return Ok(());
    }

    if let Some(path) = cli.share.clone() {
        let target = match (cli.with.clone(), cli.group.clone()) {
            (Some(user), None) => ShareTarget::User(user),
            (None, Some(group)) => ShareTarget::Group(group),
            _ => {
                return Err(
                    "--share requires exactly one of --with <username> or --group <name>".into(),
                );
            }
        };
        if cli.unshare {
            unshare_path(&config, &path, target.clone()).await?;
            println!("revoked {path} for {} {}", target.kind(), target.name());
        } else {
            let wrapped = share_path(&config, &path, target.clone()).await?;
            println!(
                "shared {path} with {} {} ({wrapped} encrypted file key(s) wrapped)",
                target.kind(),
                target.name()
            );
        }
        return Ok(());
    }

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
        // Publish the X25519 identity so others can share encrypted
        // files with this account.
        let mut identity_config = config.clone();
        identity_config.e2ee = Some(E2eeOptions {
            passphrase: Some(passphrase.clone()),
            recovery_code: None,
            prf_secret: None,
            encrypted_roots: vec!["Private".to_string()],
        });
        publish_identity(&identity_config).await?;
        println!("identity published");
        println!();
        println!("Recovery code (store it somewhere safe, it is shown once):");
        println!("  {}", recovery_code_display(&recovery));
        println!();
        println!("Losing the passphrase and the recovery code means the data is unrecoverable.");
        return Ok(());
    }

    let report = sync_once_rooted(&config, &cli.remote).await?;
    println!(
        "sync complete: pulled {}, pushed {}, removed locally {}, removed remotely {}, conflicts {}",
        report.pulled, report.pushed, report.removed_local, report.removed_remote, report.conflicts
    );
    Ok(())
}
