//! `kolimi-sync` — one-shot bidirectional sync between a local directory
//! and a Kolimi server (desktop client core alpha).

use std::error::Error;
use std::io::Write;
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use kolimi_crypto::recovery_code_display;
use kolimi_sync::{
    E2eeOptions, SharePermission, ShareTarget, SyncConfig, create_keyring, known_recipient_keys,
    migrate_mls_shares, publish_identity, share_path_with_permission, sync_once_rooted,
    unshare_path, upload_keyring,
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

    /// Enable MLS group shares (RFC 9420) for encrypted shares. Also
    /// controlled by `KOLIMI_MLS_SHARES`.
    #[arg(long, env = "KOLIMI_MLS_SHARES")]
    mls: bool,

    /// Create a write share (encrypted folders only; implies --mls).
    #[arg(long)]
    write: bool,

    /// Change an existing share to the requested permission (`--write` or
    /// `--read`) instead of creating it.
    #[arg(long)]
    update_permission: bool,

    /// Create MLS groups + keyrings for existing encrypted folder shares.
    #[arg(long)]
    mls_migrate: bool,

    /// Delete this device's sealed MLS state (recovery after corruption or
    /// state loss). A later sync publishes a new key package; an existing
    /// member must re-share each folder to add the new device.
    #[arg(long = "mls-reset")]
    mls_reset: bool,

    /// Skip the interactive confirmation for --mls-reset.
    #[arg(long)]
    yes: bool,

    /// Print the MLS epoch and members for a path.
    #[arg(long = "mls-status", value_name = "PATH")]
    mls_status: Option<String>,

    /// List this account's MLS devices, their signature keys and the shares
    /// where this client can see them.
    #[arg(long = "mls-devices")]
    mls_devices: bool,

    /// Revoke one MLS device by id: remove its leaf from every group this
    /// client can inspect, rotate the keyrings, then clear the roster entry.
    #[arg(long = "mls-revoke-device", value_name = "DEVICE_ID")]
    mls_revoke_device: Option<String>,
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

fn age_label(ms: i64) -> String {
    if ms <= 0 {
        return "never".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0);
    let seconds = ((now - ms) / 1000).max(0);
    match seconds {
        s if s < 60 => "just now".to_string(),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3600),
        s if s < 2_592_000 => format!("{}d ago", s / 86_400),
        s if s < 31_536_000 => format!("{}mo ago", s / 2_592_000),
        s => format!("{}y ago", s / 31_536_000),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let mls_command = cli.mls_devices
        || cli.mls_revoke_device.is_some()
        || cli.mls_status.is_some()
        || cli.mls_migrate;
    let needs_e2ee = !cli.e2ee_roots.is_empty() || cli.e2ee_approve.is_some() || mls_command;
    let config = SyncConfig {
        server: cli.server,
        username: cli.user,
        password: cli.password,
        token: None,
        local_dir: cli.local,
        e2ee: if !needs_e2ee {
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
                mls: cli.mls || cli.write || mls_command,
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

    if cli.mls_devices {
        let list = match cli.with.as_deref() {
            Some(user) if user != config.username => {
                kolimi_sync::mls_user_devices(&config, user).await?
            }
            _ => kolimi_sync::mls_devices(&config).await?,
        };
        if list.devices.is_empty() {
            println!("no MLS devices enrolled");
        } else {
            println!("MLS devices ({}):", list.devices.len());
            for device in list.devices {
                let name = if device.device_name.is_empty() {
                    "(unnamed)"
                } else {
                    &device.device_name
                };
                println!(
                    "  {}{}",
                    name,
                    if device.current {
                        "  (this device)"
                    } else {
                        ""
                    }
                );
                println!("    id: {}", device.device_id);
                if let Some(signature) = device.signature_key {
                    println!("    signature key: {}", STANDARD.encode(signature));
                }
                println!("    last seen: {}", age_label(device.last_seen_at));
                if device.groups.is_empty() {
                    println!("    groups: none visible from this client");
                } else {
                    println!("    groups: {}", device.groups.join(", "));
                }
            }
        }
        for warning in list.warnings {
            eprintln!("warning: cannot inspect group {warning}");
        }
        return Ok(());
    }

    if let Some(device_id) = cli.mls_revoke_device.clone() {
        if !cli.yes {
            print!(
                "Revoke MLS device {device_id}?\n\
                 This removes its leaf from every group this client can write and rotates the share keyrings.\n\
                 A read-only received share must be handled by its owner first.\n\
                 It cannot erase files or keys the device already has; it only protects future epochs.\n\
                 Type \"revoke\" to continue: "
            );
            std::io::stdout().flush()?;
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            if confirmation.trim() != "revoke" {
                println!("cancelled");
                return Ok(());
            }
        }
        let report = match cli.with.as_deref() {
            Some(user) if user != config.username => {
                kolimi_sync::mls_revoke_recipient_device(&config, user, &device_id).await?
            }
            _ => kolimi_sync::mls_revoke_device(&config, &device_id).await?,
        };
        if report.groups.is_empty() {
            println!("no MLS leaves for {device_id} were found in writable groups");
        } else {
            println!(
                "removed {} MLS leaf/leaves from {} group(s): {}",
                report.leaves,
                report.groups.len(),
                report.groups.join(", ")
            );
        }
        if report.roster_removed {
            println!("removed the MLS roster entry and unpublished packages for {device_id}");
        } else if let Some(user) = cli.with.as_deref().filter(|user| *user != config.username) {
            println!(
                "left {user}'s roster entry in place; they still need to clear any read-only shares"
            );
        }
        println!(
            "The device keeps any files and keys it already downloaded; only future epochs are protected."
        );
        return Ok(());
    }

    if cli.mls_reset {
        if !cli.yes {
            print!(
                "This deletes only this device's sealed MLS state (not your E2EE keyring or files).\n\
                 Encrypted folder shares will stop opening here until another member re-adds this device.\n\
                 Type \"reset\" to continue: "
            );
            std::io::stdout().flush()?;
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            if confirmation.trim() != "reset" {
                println!("cancelled");
                return Ok(());
            }
        }
        let removed = kolimi_sync::mls_store::MlsStore::new(&config.local_dir).reset()?;
        if removed {
            println!("removed this device's sealed MLS state");
        } else {
            println!("this device had no sealed MLS state");
        }
        println!(
            "Next steps:\n  1. run a sync to publish a new MLS key package\n  2. ask a member of each encrypted folder to re-share it with you\n  3. run sync again to join the new epoch"
        );
        return Ok(());
    }

    if let Some(path) = cli.mls_status.clone() {
        match kolimi_sync::mls_status(&config, &cli.remote, &path).await? {
            None => println!("no MLS group for {path}"),
            Some((epoch, members)) => {
                println!("{path}: epoch {epoch}");
                for (name, index) in members {
                    println!("  {name} (leaf {index})");
                }
            }
        }
        return Ok(());
    }

    if cli.mls_migrate {
        let migrated = migrate_mls_shares(&config).await?;
        if migrated.is_empty() {
            println!("no encrypted folder shares needed migration");
        } else {
            for path in migrated {
                println!("migrated {path} to an MLS group");
            }
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
            unshare_path(&config, &cli.remote, &path, target.clone()).await?;
            println!("revoked {path} for {} {}", target.kind(), target.name());
        } else if cli.update_permission {
            let permission = if cli.write {
                SharePermission::Write
            } else {
                SharePermission::Read
            };
            kolimi_sync::set_share_permission(&config, &cli.remote, &path, &target, permission)
                .await?;
            println!(
                "updated {path} for {} {} to {}",
                target.kind(),
                target.name(),
                permission.as_str()
            );
        } else {
            let permission = if cli.write {
                SharePermission::Write
            } else {
                SharePermission::Read
            };
            let wrapped =
                share_path_with_permission(&config, &cli.remote, &path, target.clone(), permission)
                    .await?;
            println!(
                "shared {path} with {} {} ({}; {wrapped} encrypted file key(s) wrapped)",
                target.kind(),
                target.name(),
                permission.as_str()
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
            mls: false,
        });
        publish_identity(&identity_config).await?;
        println!("identity published");
        println!();
        println!("Recovery phrase — 24 words (write them down, shown once):");
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
