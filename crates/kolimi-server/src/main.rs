//! Kolimi server binary: `serve` (default) plus user management CLI.

use std::{
    error::Error,
    io::BufRead,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Args, Parser, Subcommand};
use kolimi_server::{AppState, build_app};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "kolimi-server",
    version,
    about = "Kolimi server — a small, self-hosted server for files, calendars, and contacts"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Data directory (database and blob store).
    #[arg(
        long,
        global = true,
        env = "KOLIMI_DATA",
        default_value = "./kolimi-data"
    )]
    data: PathBuf,

    #[command(flatten)]
    serve: ServeArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP/WebDAV server (default when no subcommand is given).
    Serve(ServeArgs),
    /// Manage user accounts.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Manage groups.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// Back up the database snapshot and blob store.
    Backup {
        /// Destination directory (created if needed).
        #[arg(long)]
        to: PathBuf,
        /// Skip blobs already present; hard-link new ones when possible.
        #[arg(long)]
        incremental: bool,
        /// Keep the newest N marked backups in the destination's parent.
        #[arg(long, default_value_t = 0)]
        retain: usize,
        /// Optional second destination, e.g. a mounted offsite target.
        #[arg(long, env = "KOLIMI_BACKUP_OFFSITE")]
        offsite: Option<PathBuf>,
    },
    /// Verify the integrity of every stored file and version.
    Verify,
    /// Move legacy flat manifest blobs into the fanout layout.
    MigrateManifests,
    /// Inspect the append-only audit log.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Internal: sandboxed preview worker (invoked by the server itself).
    #[command(hide = true)]
    PreviewWorker {
        /// `image` or `text`.
        kind: String,
        /// Input file to read.
        input: PathBuf,
        /// Maximum thumbnail dimension.
        max: u32,
    },
}

#[derive(Args, Clone)]
struct ServeArgs {
    /// Address to bind the listener to.
    #[arg(long, env = "KOLIMI_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    /// TLS certificate (PEM). Requires --tls-key.
    #[arg(long, env = "KOLIMI_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// TLS private key (PEM). Requires --tls-cert.
    #[arg(long, env = "KOLIMI_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Set the Secure attribute on cookies (enable when serving over TLS).
    #[arg(long, env = "KOLIMI_SECURE_COOKIES")]
    secure_cookies: bool,

    /// Public origin for WebAuthn; must match the URL users visit.
    #[arg(long, env = "KOLIMI_ORIGIN", default_value = "http://localhost:8080")]
    origin: String,
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create a user.
    Add {
        username: String,
        /// Force administrator rights (the first user is always admin).
        #[arg(long)]
        admin: bool,
        /// Password (prompted if omitted).
        #[arg(long)]
        password: Option<String>,
        /// Read the password from stdin (keeps it out of the process list).
        #[arg(long)]
        password_stdin: bool,
    },
    /// Change a user's password.
    Passwd {
        username: String,
        /// Password (prompted if omitted).
        #[arg(long)]
        password: Option<String>,
    },
    /// List users.
    List,
    /// Make a user passkey-only (requires at least one registered passkey).
    PasskeyOnly { username: String },
    /// Disable TOTP for a user (admin escape hatch when codes are lost).
    TotpDisable { username: String },
    /// Recover an account: set a new password, drop sessions, and (by
    /// default) clear TOTP. Verify the user's identity out-of-band first.
    Recover {
        username: String,
        /// Password (prompted if omitted).
        #[arg(long)]
        password: Option<String>,
        /// Keep TOTP enabled (default: disabled).
        #[arg(long)]
        keep_totp: bool,
        /// Keep registered passkeys (default: remove them).
        #[arg(long)]
        keep_passkeys: bool,
    },
    /// Disable a user (rejects logins and drops their sessions).
    Disable { username: String },
    /// Re-enable a disabled user.
    Enable { username: String },
    /// Delete a user and all data they own.
    Delete {
        username: String,
        /// Confirm the deletion (required).
        #[arg(long)]
        yes: bool,
    },
    /// Set a user's storage quota (`<bytes>`, `unlimited`, or `default`).
    Quota { username: String, value: String },
    /// Show a user's storage usage and quota.
    Usage {
        username: String,
        /// Recompute from disk instead of using the cached counter.
        #[arg(long)]
        reconcile: bool,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// List recent audit entries, newest first (JSON lines).
    List {
        /// Maximum number of entries.
        #[arg(long, default_value_t = 50)]
        limit: i64,
        /// Only entries with a smaller id.
        #[arg(long)]
        before: Option<i64>,
    },
    /// Verify the hash chain, checkpoint headers, signatures, and anchors.
    Verify {
        /// Trusted Ed25519 public key (hex); repeatable.
        #[arg(long)]
        trusted_key: Vec<String>,
        /// File with `key_id public_key_hex [label]` lines.
        #[arg(long)]
        trusted_keys: Option<PathBuf>,
        /// JSONL anchor log to cross-check.
        #[arg(long)]
        anchor_log: Option<PathBuf>,
        /// Fail on any checkpoint without a valid trusted signature.
        #[arg(long)]
        require_signatures: bool,
    },
    /// Seal unsealed entries into audit checkpoints.
    Seal {
        /// Maximum entries per checkpoint batch.
        #[arg(long, default_value_t = 4096)]
        batch: i64,
        /// Signing key file (defaults to KOLIMI_AUDIT_SIGNING_KEY).
        #[arg(long, env = "KOLIMI_AUDIT_SIGNING_KEY")]
        key: Option<PathBuf>,
    },
    /// Sign existing checkpoints (backfill or key rotation).
    Sign {
        /// Signing key file (defaults to KOLIMI_AUDIT_SIGNING_KEY).
        #[arg(long, env = "KOLIMI_AUDIT_SIGNING_KEY")]
        key: PathBuf,
        /// Specific checkpoint id; repeatable.
        #[arg(long = "checkpoint")]
        checkpoint: Vec<i64>,
        /// Sign every checkpoint lacking this key's signature.
        #[arg(long)]
        all: bool,
    },
    /// Generate an Ed25519 audit signing key.
    Keygen {
        /// New key file (must not exist).
        #[arg(long)]
        out: PathBuf,
        /// Optional operator label.
        #[arg(long)]
        label: Option<String>,
    },
    /// Print the latest checkpoint's anchor record.
    Head {
        /// Pretty-print the JSON.
        #[arg(long)]
        json: bool,
    },
    /// List sealed checkpoint headers.
    Checkpoints {
        /// Maximum number of headers.
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// Export a sealed checkpoint and prune its entry bodies.
    Prune {
        /// Checkpoint id to export and prune.
        #[arg(long, conflicts_with = "before")]
        checkpoint: Option<i64>,
        /// Legacy alias: the entry id where a sealed checkpoint ends.
        #[arg(long)]
        before: Option<i64>,
        /// JSONL export path (must not exist).
        #[arg(long)]
        to: PathBuf,
    },
    /// Verify a sealed checkpoint export bundle.
    VerifyExport {
        /// JSONL bundle written by `audit prune`.
        #[arg(long)]
        file: PathBuf,
        /// Trusted Ed25519 public key (hex); repeatable.
        #[arg(long)]
        trusted_key: Vec<String>,
    },
    /// Inspect or drain the anchor outbox.
    Anchors {
        #[command(subcommand)]
        command: AnchorCommand,
    },
}

#[derive(Subcommand)]
enum AnchorCommand {
    /// List anchor-outbox rows, newest first.
    List {
        /// Maximum number of rows.
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// Attempt delivery to the configured sinks now.
    Flush,
}

#[derive(Subcommand)]
enum GroupCommand {
    /// Create a group.
    Add { name: String },
    /// List groups and their members.
    List,
    /// Add a user to a group.
    AddMember { group: String, username: String },
    /// Remove a user from a group.
    RemoveMember { group: String, username: String },
    /// Delete a group (its shares are revoked).
    Delete { name: String },
}

/// Initializes tracing: plain `fmt` by default, plus OTLP export when built
/// with `--features otel` and `KOLIMI_OTEL_ENDPOINT` is set.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    #[cfg(feature = "otel")]
    {
        if let Ok(endpoint) = std::env::var("KOLIMI_OTEL_ENDPOINT") {
            match init_otel(&endpoint) {
                Ok(tracer) => {
                    use tracing_subscriber::layer::SubscriberExt;
                    use tracing_subscriber::util::SubscriberInitExt;
                    tracing_subscriber::registry()
                        .with(filter)
                        .with(tracing_subscriber::fmt::layer())
                        .with(tracing_opentelemetry::layer().with_tracer(tracer))
                        .init();
                    tracing::info!(%endpoint, "OpenTelemetry OTLP trace export enabled");
                    return;
                }
                Err(error) => {
                    eprintln!("OpenTelemetry init failed ({error}); continuing without traces");
                }
            }
        }
    }

    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Builds the OTLP/gRPC trace exporter and installs it as the global
/// tracer provider. Returns the tracer for the `tracing` layer.
#[cfg(feature = "otel")]
fn init_otel(
    endpoint: &str,
) -> Result<opentelemetry_sdk::trace::SdkTracer, Box<dyn std::error::Error>> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(Resource::builder().with_service_name("kolimi").build())
        .build();
    let tracer = provider.tracer("kolimi");
    opentelemetry::global::set_tracer_provider(provider);
    Ok(tracer)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let cli = Cli::parse();
    let Cli {
        command,
        data,
        serve: serve_args,
    } = cli;
    match command {
        None => serve(serve_args, data).await,
        Some(Command::Serve(args)) => serve(args, data).await,
        Some(Command::User { command }) => user_command(command, data).await,
        Some(Command::Group { command }) => group_command(command, data).await,
        Some(Command::Backup {
            to,
            incremental,
            retain,
            offsite,
        }) => backup(data, to, incremental, retain, offsite).await,
        Some(Command::Verify) => verify(data).await,
        Some(Command::MigrateManifests) => migrate_manifests(data).await,
        Some(Command::Audit { command }) => audit_command(command, data).await,
        Some(Command::PreviewWorker { kind, input, max }) => {
            match kolimi_preview::worker::run(&kind, &input, max) {
                Ok(()) => std::process::exit(0),
                Err(error) => {
                    eprintln!("preview worker: {error}");
                    std::process::exit(1);
                }
            }
        }
    }
}

async fn serve(args: ServeArgs, data: PathBuf) -> Result<(), Box<dyn Error>> {
    let mut state = AppState::init(&data, args.secure_cookies, &args.origin).await?;
    let audit_signing_key = std::env::var_os("KOLIMI_AUDIT_SIGNING_KEY").map(PathBuf::from);
    let audit_signer = match audit_signing_key.as_deref() {
        Some(path) => match kolimi_db::AuditSigner::load(path) {
            Ok(signer) => {
                tracing::info!(key_id = signer.key_id(), "audit checkpoint signing enabled");
                Some(std::sync::Arc::new(signer))
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    "audit signing key unavailable; sealing will be refused until it is fixed"
                );
                None
            }
        },
        None => None,
    };
    state = state.with_audit_signing(audit_signing_key, audit_signer);
    match kolimi_server::anchor::AnchorConfig::from_env() {
        Ok(Some(config)) => {
            tracing::info!(
                journal = config
                    .journal
                    .as_ref()
                    .map(|path| path.display().to_string()),
                url = config.url.as_deref().unwrap_or(""),
                "audit checkpoint anchoring enabled"
            );
            state = state.with_audit_anchors(Some(std::sync::Arc::new(config)));
        }
        Ok(None) => {}
        Err(error) => tracing::error!(%error, "audit anchoring disabled by configuration error"),
    }
    tokio::spawn(kolimi_server::janitor::run(state.clone()));
    tokio::spawn(kolimi_server::search_indexer::run(state.clone()));
    let app = build_app(state);

    match (args.tls_cert, args.tls_key) {
        (Some(cert), Some(key)) => {
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
            });
            tracing::info!(bind = %args.bind, tls = true, "kolimi server listening");
            axum_server::bind_rustls(args.bind, config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        (None, None) => {
            if !args.bind.ip().is_loopback() {
                tracing::warn!("TLS is disabled and the listener is not on loopback");
            }
            let listener = tokio::net::TcpListener::bind(args.bind).await?;
            tracing::info!(bind = %args.bind, tls = false, "kolimi server listening");
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        }
        _ => return Err("--tls-cert and --tls-key must be provided together".into()),
    }

    tracing::info!("kolimi server stopped");
    Ok(())
}

async fn user_command(command: UserCommand, data: PathBuf) -> Result<(), Box<dyn Error>> {
    tokio::fs::create_dir_all(&data).await?;
    let db = kolimi_db::Db::connect(&data.join("kolimi.db")).await?;

    match command {
        UserCommand::Add {
            username,
            admin,
            password,
            password_stdin,
        } => {
            let password = if password_stdin {
                read_password_from_stdin()?
            } else {
                match password {
                    Some(password) => password,
                    None => read_password(&format!("Password for {username}: "))?,
                }
            };
            let hash = kolimi_auth::password::hash_password(&password)?;
            let user = db.create_user(&username, &hash).await?;
            if admin && !user.is_admin {
                db.set_admin(user.id, true).await?;
            }
            db.audit_append(
                None,
                Some("cli"),
                "user.add",
                &user.username,
                &serde_json::json!({ "admin": user.is_admin || admin }),
            )
            .await?;
            println!(
                "created user {} (id {}, admin: {})",
                user.username,
                user.id,
                user.is_admin || admin
            );
        }
        UserCommand::Passwd { username, password } => {
            let password = match password {
                Some(password) => password,
                None => read_password(&format!("New password for {username}: "))?,
            };
            let hash = kolimi_auth::password::hash_password(&password)?;
            db.set_password(&username, &hash).await?;
            // A password change must not leave existing sessions alive.
            if let Some(user) = db.find_user(&username).await? {
                db.delete_user_sessions(user.id).await?;
            }
            db.audit_append(
                None,
                Some("cli"),
                "user.passwd",
                &username,
                &serde_json::json!({}),
            )
            .await?;
            println!("password updated for {username}");
        }
        UserCommand::PasskeyOnly { username } => {
            let user = db
                .find_user(&username)
                .await?
                .ok_or_else(|| format!("no such user: {username}"))?;
            let passkeys = db.count_passkeys(user.id).await?;
            if passkeys == 0 {
                return Err(format!(
                    "{username} has no passkeys; register one before going passkey-only"
                )
                .into());
            }
            db.clear_password(&username).await?;
            db.audit_append(
                None,
                Some("cli"),
                "user.passkey_only",
                &username,
                &serde_json::json!({ "passkeys": passkeys }),
            )
            .await?;
            println!("{username} is now passkey-only ({passkeys} passkeys)");
        }
        UserCommand::TotpDisable { username } => {
            let user = db
                .find_user(&username)
                .await?
                .ok_or_else(|| format!("no such user: {username}"))?;
            db.clear_totp(user.id).await?;
            db.audit_append(
                None,
                Some("cli"),
                "totp.admin_disable",
                &username,
                &serde_json::json!({}),
            )
            .await?;
            println!("two-factor disabled for {username}");
        }
        UserCommand::Recover {
            username,
            password,
            keep_totp,
            keep_passkeys,
        } => {
            let password = match password {
                Some(password) => password,
                None => read_password(&format!("New password for {username}: "))?,
            };
            let hash = kolimi_auth::password::hash_password(&password)?;
            let report = kolimi_server::admin::recover_user(
                &db,
                &username,
                &hash,
                keep_totp,
                !keep_passkeys,
            )
            .await?;
            println!(
                "recovered {username}: password set, {} session(s) and {} app password(s) dropped, TOTP {}, {} passkey(s) removed",
                report.sessions_dropped,
                report.app_passwords_revoked,
                if report.totp_disabled {
                    "disabled"
                } else {
                    "kept"
                },
                report.passkeys_removed,
            );
        }
        UserCommand::Disable { username } => {
            db.set_disabled(&username, true).await?;
            db.audit_append(
                None,
                Some("cli"),
                "user.disable",
                &username,
                &serde_json::json!({}),
            )
            .await?;
            println!("disabled {username}");
        }
        UserCommand::Enable { username } => {
            db.set_disabled(&username, false).await?;
            db.audit_append(
                None,
                Some("cli"),
                "user.enable",
                &username,
                &serde_json::json!({}),
            )
            .await?;
            println!("enabled {username}");
        }
        UserCommand::Delete { username, yes } => {
            if !yes {
                return Err(format!("refusing to delete {username} without --yes").into());
            }
            let user = db
                .find_user(&username)
                .await?
                .ok_or_else(|| format!("no such user: {username}"))?;
            db.delete_user(&username).await?;
            // Blob storage is per-user and the janitor only visits
            // existing users, so remove it here or it leaks forever.
            let store = kolimi_store::BlobStore::open(data.join("blobs")).await?;
            if let Err(error) = store.remove_user(user.id).await {
                eprintln!("warning: could not remove blob data for {username}: {error}");
            }
            // The DB cascades don't reach the search index: drop the
            // user's documents too, or their filenames stay searchable.
            // Best-effort, like the blob cleanup above.
            match kolimi_search::SearchIndex::open(&data.join("search")) {
                Ok(search) => {
                    if let Err(error) = search.delete_user(user.id).and_then(|()| search.commit()) {
                        eprintln!(
                            "warning: could not remove search data for {username}: {error} (the server holds the index lock while running; leftovers are pruned automatically on the next server start)"
                        );
                    }
                }
                Err(error) => {
                    eprintln!("warning: could not open search index for {username}: {error}");
                }
            }
            db.audit_append(
                None,
                Some("cli"),
                "user.delete",
                &username,
                &serde_json::json!({}),
            )
            .await?;
            println!("deleted {username} and all owned data");
        }
        UserCommand::Quota { username, value } => {
            let user = db
                .find_user(&username)
                .await?
                .ok_or_else(|| format!("no such user: {username}"))?;
            let quota: Option<i64> = match value.as_str() {
                "unlimited" => Some(0),
                "default" => None,
                other => Some(other.parse::<i64>().map_err(|_| {
                    format!("invalid quota '{other}' (use bytes, 'unlimited' or 'default')")
                })?),
            };
            if let Some(bytes) = quota
                && bytes < 0
            {
                return Err("quota must be >= 0".into());
            }
            db.set_quota_bytes(user.id, quota).await?;
            db.audit_append(
                None,
                Some("cli"),
                "user.quota",
                &username,
                &serde_json::json!({ "quota_bytes": quota }),
            )
            .await?;
            match quota {
                Some(0) => println!("{username}: unlimited storage"),
                Some(bytes) => println!("{username}: quota set to {bytes} bytes"),
                None => println!("{username}: using the server default quota"),
            }
        }
        UserCommand::Usage {
            username,
            reconcile,
        } => {
            let user = db
                .find_user(&username)
                .await?
                .ok_or_else(|| format!("no such user: {username}"))?;
            let used = if reconcile {
                let store = kolimi_store::BlobStore::open(data.join("blobs")).await?;
                let vfs = kolimi_vfs::Vfs::new(db.clone(), store);
                let bytes = vfs.referenced_bytes(user.id).await?;
                db.set_used_bytes(user.id, bytes, kolimi_db::now_millis())
                    .await?;
                bytes
            } else {
                user.used_bytes.max(0) as u64
            };
            let default_quota = std::env::var("KOLIMI_USER_QUOTA_BYTES")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            let effective = match user.quota_bytes {
                Some(q) if q > 0 => q as u64,
                Some(_) => 0,
                None => default_quota,
            };
            let quota = if effective == 0 {
                "unlimited".to_string()
            } else {
                format!("{effective} bytes")
            };
            let source = if reconcile { " (recomputed)" } else { "" };
            println!("{username}: used {used} bytes of {quota}{source}");
        }
        UserCommand::List => {
            for user in db.list_users().await? {
                println!(
                    "{}\t{}\tadmin={}\tdisabled={}",
                    user.id, user.username, user.is_admin, user.disabled
                );
            }
        }
    }
    Ok(())
}

async fn group_command(command: GroupCommand, data: PathBuf) -> Result<(), Box<dyn Error>> {
    tokio::fs::create_dir_all(&data).await?;
    let db = kolimi_db::Db::connect(&data.join("kolimi.db")).await?;

    match command {
        GroupCommand::Add { name } => {
            let group = db.create_group(&name).await?;
            db.audit_append(
                None,
                Some("cli"),
                "group.add",
                &group.name,
                &serde_json::json!({ "id": group.id }),
            )
            .await?;
            println!("created group {} (id {})", group.name, group.id);
        }
        GroupCommand::List => {
            for group in db.list_groups().await? {
                let members = db.group_members(group.id).await?;
                let names: Vec<&str> = members.iter().map(|m| m.username.as_str()).collect();
                println!(
                    "{}\t{}\tmembers: {}",
                    group.id,
                    group.name,
                    names.join(", ")
                );
            }
        }
        GroupCommand::AddMember { group, username } => {
            let group = db
                .group_by_name(&group)
                .await?
                .ok_or_else(|| format!("no such group: {group}"))?;
            let user = db
                .find_user(&username)
                .await?
                .ok_or_else(|| format!("no such user: {username}"))?;
            db.add_group_member(group.id, user.id).await?;
            db.audit_append(
                None,
                Some("cli"),
                "group.member_add",
                &group.name,
                &serde_json::json!({ "user": user.username }),
            )
            .await?;
            println!("added {} to {}", user.username, group.name);
        }
        GroupCommand::RemoveMember { group, username } => {
            let group = db
                .group_by_name(&group)
                .await?
                .ok_or_else(|| format!("no such group: {group}"))?;
            let user = db
                .find_user(&username)
                .await?
                .ok_or_else(|| format!("no such user: {username}"))?;
            if db.remove_group_member(group.id, user.id).await? {
                db.audit_append(
                    None,
                    Some("cli"),
                    "group.member_remove",
                    &group.name,
                    &serde_json::json!({ "user": user.username }),
                )
                .await?;
                println!("removed {} from {}", user.username, group.name);
            } else {
                println!("{} was not a member of {}", user.username, group.name);
            }
        }
        GroupCommand::Delete { name } => {
            let group = db
                .group_by_name(&name)
                .await?
                .ok_or_else(|| format!("no such group: {name}"))?;
            db.delete_group(group.id).await?;
            db.audit_append(
                None,
                Some("cli"),
                "group.delete",
                &group.name,
                &serde_json::json!({ "id": group.id }),
            )
            .await?;
            println!("deleted group {}", group.name);
        }
    }
    Ok(())
}

async fn backup(
    data: PathBuf,
    to: PathBuf,
    incremental: bool,
    retain: usize,
    offsite: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    tokio::fs::create_dir_all(&to).await?;
    let db = kolimi_db::Db::connect(&data.join("kolimi.db")).await?;
    let db_target = to.join("kolimi.db");
    if tokio::fs::try_exists(&db_target).await? {
        tokio::fs::remove_file(&db_target).await?;
    }
    db.backup_to(&db_target).await?;

    let store = kolimi_store::BlobStore::open(data.join("blobs")).await?;
    if incremental {
        let stats = store.copy_tree_incremental_to(&to.join("blobs")).await?;
        println!(
            "incremental backup complete: database snapshot, {} linked + {} copied blobs, {} already present, {} bytes copied, written to {}",
            stats.linked,
            stats.copied,
            stats.skipped,
            stats.bytes_copied,
            to.display()
        );
    } else {
        let blobs = store.copy_tree_to(&to.join("blobs")).await?;
        println!(
            "backup complete: database snapshot + {blobs} blobs written to {}",
            to.display()
        );
    }
    write_backup_marker(&to).await?;

    if let Some(offsite) = offsite {
        let stats = mirror_backup(&to, &offsite).await?;
        println!(
            "offsite mirror complete: {} linked + {} copied blobs, {} already present, {} bytes copied, written to {}",
            stats.linked,
            stats.copied,
            stats.skipped,
            stats.bytes_copied,
            offsite.display()
        );
    }

    if retain > 0 {
        let pruned = prune_backups(&to, retain).await?;
        if pruned > 0 {
            println!("retention: pruned {pruned} old backup(s), keeping {retain}");
        }
    }
    Ok(())
}

const BACKUP_MARKER: &str = "kolimi-backup.json";

/// Writes the marker that identifies a directory as a Kolimi backup. Only
/// marked directories are eligible for retention pruning.
async fn write_backup_marker(dir: &Path) -> Result<(), Box<dyn Error>> {
    let marker = serde_json::json!({
        "format": "kolimi-backup",
        "version": 1,
        "created_at": kolimi_db::now_millis(),
    });
    let temp = dir.join(format!(".{BACKUP_MARKER}.tmp-{}", kolimi_db::now_millis()));
    let target = dir.join(BACKUP_MARKER);
    tokio::fs::write(&temp, marker.to_string()).await?;
    if tokio::fs::try_exists(&target).await? {
        tokio::fs::remove_file(&target).await?;
    }
    tokio::fs::rename(&temp, &target).await?;
    Ok(())
}

/// Mirrors a completed backup to a second directory. The destination is
/// normally a mount point for NFS, SMB, rclone, or an object-store FUSE
/// mount; blobs are hard-linked when the filesystem supports it.
async fn mirror_backup(
    source: &Path,
    dest: &Path,
) -> Result<kolimi_store::BlobCopyStats, Box<dyn Error>> {
    tokio::fs::create_dir_all(dest).await?;

    let store = kolimi_store::BlobStore::open(source.join("blobs")).await?;
    let stats = store.copy_tree_incremental_to(&dest.join("blobs")).await?;

    let db_source = source.join("kolimi.db");
    let db_target = dest.join("kolimi.db");
    let temp = dest.join(format!(".kolimi.db.tmp-{}", kolimi_db::now_millis()));
    tokio::fs::copy(&db_source, &temp).await?;
    {
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&temp)
            .await?;
        file.sync_all().await?;
    }
    if tokio::fs::try_exists(&db_target).await? {
        tokio::fs::remove_file(&db_target).await?;
    }
    tokio::fs::rename(&temp, &db_target).await?;
    tokio::fs::copy(source.join(BACKUP_MARKER), dest.join(BACKUP_MARKER)).await?;
    Ok(stats)
}

/// Prunes the oldest marked sibling backups, keeping the newest `retain`.
async fn prune_backups(target: &Path, retain: usize) -> Result<usize, Box<dyn Error>> {
    if retain == 0 {
        return Ok(0);
    }
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let mut backups: Vec<(i64, String, PathBuf)> = Vec::new();
    let mut entries = match tokio::fs::read_dir(parent).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await?.is_dir() {
            continue;
        }
        let path = entry.path();
        let Ok(marker) = tokio::fs::read_to_string(path.join(BACKUP_MARKER)).await else {
            continue;
        };
        let Ok(marker) = serde_json::from_str::<serde_json::Value>(&marker) else {
            continue;
        };
        if marker["format"] != "kolimi-backup" {
            continue;
        }
        backups.push((
            marker["created_at"].as_i64().unwrap_or(0),
            entry.file_name().to_string_lossy().to_string(),
            path,
        ));
    }
    // Newest first; the name breaks ties when two backups share a millisecond.
    backups.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
    let mut pruned = 0;
    for (_, _, path) in backups.into_iter().skip(retain) {
        if path == target {
            continue;
        }
        tokio::fs::remove_dir_all(&path).await?;
        println!("pruned old backup {}", path.display());
        pruned += 1;
    }
    Ok(pruned)
}

async fn verify(data: PathBuf) -> Result<(), Box<dyn Error>> {
    let db = kolimi_db::Db::connect(&data.join("kolimi.db")).await?;
    let store = kolimi_store::BlobStore::open(data.join("blobs")).await?;
    let vfs = kolimi_vfs::Vfs::new(db.clone(), store);

    let mut failures = 0u64;
    let users = db.list_users().await?;
    if users.is_empty() {
        println!("no users to verify");
    }
    for user in users {
        match vfs.verify_all(user.id).await {
            Ok((chunks, bytes)) => {
                println!("{}: {chunks} chunks, {bytes} bytes verified", user.username);
            }
            Err(error) => {
                failures += 1;
                eprintln!("{}: FAILED: {error}", user.username);
            }
        }
    }
    if failures > 0 {
        return Err(format!("{failures} user(s) failed verification").into());
    }
    println!("all content verified");
    Ok(())
}

async fn migrate_manifests(data: PathBuf) -> Result<(), Box<dyn Error>> {
    let db = kolimi_db::Db::connect(&data.join("kolimi.db")).await?;
    let store = kolimi_store::BlobStore::open(data.join("blobs")).await?;
    let mut total = 0u64;
    for user in db.list_users().await? {
        let moved = store.migrate_legacy_manifests(user.id, usize::MAX).await?;
        if moved > 0 {
            println!("{}: moved {moved} legacy manifests", user.username);
        }
        db.mark_legacy_manifests_migrated(user.id).await?;
        total += moved;
    }
    println!("migrated {total} legacy manifests");
    Ok(())
}

async fn audit_command(command: AuditCommand, data: PathBuf) -> Result<(), Box<dyn Error>> {
    tokio::fs::create_dir_all(&data).await?;
    let db = kolimi_db::Db::connect(&data.join("kolimi.db")).await?;

    match command {
        AuditCommand::List { limit, before } => {
            for entry in db.audit_list(limit, before).await? {
                let details: serde_json::Value =
                    serde_json::from_str(&entry.details).unwrap_or(serde_json::Value::Null);
                println!(
                    "{}",
                    serde_json::json!({
                        "id": entry.id,
                        "ts": entry.ts,
                        "actor_id": entry.actor_id,
                        "actor": entry.actor,
                        "action": entry.action,
                        "subject": entry.subject,
                        "details": details,
                    })
                );
            }
        }
        AuditCommand::Verify {
            trusted_key,
            trusted_keys,
            anchor_log,
            require_signatures,
        } => {
            let mut keys = Vec::new();
            for key in trusted_key {
                keys.push(kolimi_db::TrustedAuditKey::from_hex(&key)?);
            }
            if let Some(path) = trusted_keys {
                keys.extend(kolimi_db::TrustedAuditKey::parse_file(&path)?);
            }
            let mut trust_source = if keys.is_empty() {
                "none".to_string()
            } else {
                "trusted-keys".to_string()
            };
            if keys.is_empty()
                && let Some(path) = std::env::var_os("KOLIMI_AUDIT_SIGNING_KEY")
            {
                match kolimi_db::AuditSigner::load(Path::new(&path)) {
                    Ok(signer) => {
                        keys.push(kolimi_db::TrustedAuditKey::from_parts(
                            signer.key_id(),
                            signer.public_key().to_vec(),
                        )?);
                        trust_source = "configured-key".to_string();
                    }
                    Err(error) => eprintln!("configured signing key unavailable: {error}"),
                }
            }
            let verify = db
                .audit_verify_with(kolimi_db::AuditVerifyOptions {
                    trusted_keys: keys,
                    require_signatures,
                    anchor_log,
                    trust_source: Some(trust_source),
                })
                .await?;
            match verify.first_bad {
                None => println!(
                    "audit chain ok ({} entries, {} checkpoints, {} pruned)",
                    verify.entries, verify.checkpoints, verify.pruned_checkpoints
                ),
                Some(id) => {
                    eprintln!(
                        "audit chain BROKEN at entry {id} ({} entries, {} checkpoints checked)",
                        verify.entries, verify.checkpoints
                    );
                }
            }
            println!(
                "signatures: {} signed, {} verified, {} unsigned, {} untrusted, {} errors (trust: {})",
                verify.signed_checkpoints,
                verify.verified_signatures,
                verify.unsigned_checkpoints,
                verify.untrusted_signatures,
                verify.signature_errors,
                verify.trust_source
            );
            if verify.rollback_detected {
                eprintln!("ROLLBACK DETECTED: a published anchor is newer than local history");
            }
            if let Some(latest) = &verify.latest_anchor {
                println!(
                    "anchors: {} checked, latest checkpoint {} through entry {}",
                    verify.anchors_checked, latest.checkpoint_id, latest.last_entry_id
                );
            } else if verify.anchors_checked > 0 {
                println!("anchors: {} checked", verify.anchors_checked);
            }
            if let Some(latest) = verify.latest_checkpoint {
                println!(
                    "latest checkpoint: {} through entry {} (root {})",
                    latest.id, latest.last_entry_id, latest.merkle_root
                );
            }
            if let Some(anchor) = db.audit_anchor().await? {
                println!(
                    "anchor: entries through {} were pruned ({} total)",
                    anchor.pruned_through, anchor.pruned_entries
                );
            }
            if verify.first_bad.is_some() || verify.signature_errors > 0 || verify.rollback_detected
            {
                std::process::exit(1);
            }
        }
        AuditCommand::Seal { batch, key } => {
            let signer = match key {
                Some(path) => Some(kolimi_db::AuditSigner::load(&path)?),
                None => None,
            };
            let anchors = kolimi_server::anchor::AnchorConfig::from_env()
                .map_err(|error| format!("audit anchoring: {error}"))?;
            let enqueue_anchor = anchors.as_ref().is_some_and(|config| config.enabled());
            let mut sealed = 0u64;
            while let Some(checkpoint) = db
                .audit_seal_with(batch, signer.as_ref(), enqueue_anchor)
                .await?
            {
                println!(
                    "sealed checkpoint {}: entries {}..={} ({} entries, root {}{})",
                    checkpoint.id,
                    checkpoint.first_entry_id,
                    checkpoint.last_entry_id,
                    checkpoint.entry_count,
                    hex::encode(&checkpoint.merkle_root),
                    if signer.is_some() { ", signed" } else { "" }
                );
                sealed += 1;
            }
            if sealed == 0 {
                println!("no unsealed audit entries");
            }
            if let (Some(config), true) = (anchors.as_ref(), enqueue_anchor) {
                match kolimi_server::anchor::drain(&db, config, None, 100).await {
                    Ok(report) => println!(
                        "anchors: {} journaled, {} delivered, {} failed",
                        report.journaled, report.delivered, report.failed
                    ),
                    Err(error) => eprintln!("anchor drain failed: {error}"),
                }
            }
        }
        AuditCommand::Sign {
            key,
            checkpoint,
            all,
        } => {
            let signer = kolimi_db::AuditSigner::load(&key)?;
            if all && !checkpoint.is_empty() {
                return Err("use either --checkpoint or --all, not both".into());
            }
            let signed = if all {
                db.audit_sign_checkpoints(None, true, &signer).await?
            } else if checkpoint.is_empty() {
                return Err("specify --checkpoint ID or --all".into());
            } else {
                let mut count = 0;
                for id in checkpoint {
                    count += db.audit_sign_checkpoints(Some(id), false, &signer).await?;
                }
                count
            };
            println!("signed {signed} checkpoint(s) with key {}", signer.key_id());
        }
        AuditCommand::Keygen { out, label } => {
            let signer = kolimi_db::AuditSigner::generate(&out, label.as_deref())?;
            println!("key id: {}", signer.key_id());
            println!("public key: {}", signer.public_key_hex());
            println!("wrote {}", out.display());
        }
        AuditCommand::Head { json } => match db.audit_anchor_record(None).await? {
            Some(record) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&record)?);
                } else {
                    println!("{}", serde_json::to_string(&record)?);
                }
            }
            None => println!("no sealed checkpoints"),
        },
        AuditCommand::Checkpoints { limit } => {
            for checkpoint in db.audit_checkpoints(limit).await? {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": checkpoint.id,
                        "first_entry_id": checkpoint.first_entry_id,
                        "last_entry_id": checkpoint.last_entry_id,
                        "entry_count": checkpoint.entry_count,
                        "prev_checkpoint_hash": hex::encode(&checkpoint.prev_checkpoint_hash),
                        "merkle_root": hex::encode(&checkpoint.merkle_root),
                        "checkpoint_hash": hex::encode(&checkpoint.checkpoint_hash),
                        "created_at": checkpoint.created_at,
                        "pruned": checkpoint.entries_pruned_at.is_some(),
                        "entries_pruned_at": checkpoint.entries_pruned_at,
                    })
                );
            }
        }
        AuditCommand::Prune {
            checkpoint,
            before,
            to,
        } => {
            let checkpoint_id = match (checkpoint, before) {
                (Some(id), None) => id,
                (None, Some(entry_id)) => db
                    .audit_checkpoint_ending_at(entry_id)
                    .await?
                    .map(|checkpoint| checkpoint.id)
                    .ok_or_else(|| {
                        format!(
                            "no sealed checkpoint ends at entry {entry_id}; run `audit seal` first"
                        )
                    })?,
                _ => {
                    return Err("specify exactly one of --checkpoint or --before".into());
                }
            };
            let report = db
                .audit_export_and_prune_checkpoint(checkpoint_id, &to)
                .await?;
            println!(
                "exported {} audit entries through {} to {} (checkpoint {}, anchor {})",
                report.exported,
                report.pruned_through,
                to.display(),
                report.checkpoint_id.unwrap_or(checkpoint_id),
                report.anchor_hash
            );
        }
        AuditCommand::VerifyExport { file, trusted_key } => {
            let mut keys = Vec::new();
            for key in trusted_key {
                keys.push(kolimi_db::TrustedAuditKey::from_hex(&key)?);
            }
            match db.audit_verify_export_with(&file, &keys).await {
                Ok(verify) => println!(
                    "export ok: checkpoint {} with {} entries, {} signatures ({} trusted)",
                    verify.checkpoint_id,
                    verify.entries,
                    verify.signatures,
                    verify.trusted_signatures
                ),
                Err(error) => {
                    eprintln!("export BROKEN: {error}");
                    std::process::exit(1);
                }
            }
        }
        AuditCommand::Anchors { command } => match command {
            AnchorCommand::List { limit } => {
                for row in db.audit_anchor_outbox(limit).await? {
                    println!(
                        "{}",
                        serde_json::json!({
                            "checkpoint_id": row.checkpoint_id,
                            "journaled_at": row.journaled_at,
                            "delivered_at": row.delivered_at,
                            "attempts": row.attempts,
                            "next_attempt_at": row.next_attempt_at,
                            "last_error": row.last_error,
                        })
                    );
                }
            }
            AnchorCommand::Flush => {
                let config = kolimi_server::anchor::AnchorConfig::from_env()
                    .map_err(|error| format!("audit anchoring: {error}"))?
                    .ok_or("no anchor sinks configured (set KOLIMI_AUDIT_ANCHOR_LOG or KOLIMI_AUDIT_ANCHOR_URL)")?;
                let report = kolimi_server::anchor::drain(&db, &config, None, 100).await?;
                println!(
                    "anchors: {} journaled, {} delivered, {} failed",
                    report.journaled, report.delivered, report.failed
                );
            }
        },
    }
    Ok(())
}

fn read_password(prompt: &str) -> Result<String, Box<dyn Error>> {
    match rpassword::prompt_password(prompt) {
        Ok(password) => Ok(password),
        Err(_) => {
            eprint!("{prompt}");
            let stdin = std::io::stdin();
            let mut line = String::new();
            stdin.lock().read_line(&mut line)?;
            Ok(line.trim_end().to_string())
        }
    }
}

/// Reads a password from stdin unconditionally (no TTY prompt), so a script
/// can supply it without exposing it in the process list.
fn read_password_from_stdin() -> Result<String, Box<dyn Error>> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn data_flag_is_global() {
        let cli =
            Cli::try_parse_from(["kolimi-server", "--data", "/tmp/a", "user", "list"]).unwrap();
        assert_eq!(cli.data, PathBuf::from("/tmp/a"));

        // Global flags parse after the subcommand too.
        let cli =
            Cli::try_parse_from(["kolimi-server", "user", "list", "--data", "/tmp/b"]).unwrap();
        assert_eq!(cli.data, PathBuf::from("/tmp/b"));

        let cli = Cli::try_parse_from([
            "kolimi-server",
            "backup",
            "--to",
            "/tmp/backup",
            "--data",
            "/tmp/c",
        ])
        .unwrap();
        assert_eq!(cli.data, PathBuf::from("/tmp/c"));
    }
}
