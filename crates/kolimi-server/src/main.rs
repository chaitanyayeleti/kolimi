//! Kolimi server binary: `serve` (default) plus user management CLI.

use std::{error::Error, io::BufRead, net::SocketAddr, path::PathBuf, time::Duration};

use clap::{Args, Parser, Subcommand};
use kolimi_server::{AppState, build_app};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "kolimi-server",
    version,
    about = "Kolimi server — a pure-Rust, single-binary alternative to Nextcloud"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

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
        /// Data directory to back up.
        #[arg(long, env = "KOLIMI_DATA", default_value = "./kolimi-data")]
        data: PathBuf,
        /// Destination directory (created if needed).
        #[arg(long)]
        to: PathBuf,
    },
    /// Verify the integrity of every stored file and version.
    Verify {
        /// Data directory to verify.
        #[arg(long, env = "KOLIMI_DATA", default_value = "./kolimi-data")]
        data: PathBuf,
    },
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

    /// Data directory (database and blob store).
    #[arg(long, env = "KOLIMI_DATA", default_value = "./kolimi-data")]
    data: PathBuf,

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
        /// Also delete all of the user's registered passkeys.
        #[arg(long)]
        remove_passkeys: bool,
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
    /// Verify the hash chain (exit 1 if broken).
    Verify,
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
    match cli.command {
        None => serve(cli.serve).await,
        Some(Command::Serve(args)) => serve(args).await,
        Some(Command::User { command }) => user_command(command).await,
        Some(Command::Group { command }) => group_command(command).await,
        Some(Command::Backup { data, to }) => backup(data, to).await,
        Some(Command::Verify { data }) => verify(data).await,
        Some(Command::Audit { command }) => audit_command(command).await,
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

async fn serve(args: ServeArgs) -> Result<(), Box<dyn Error>> {
    let state = AppState::init(&args.data, args.secure_cookies, &args.origin).await?;
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

async fn user_command(command: UserCommand) -> Result<(), Box<dyn Error>> {
    let data: PathBuf =
        std::env::var("KOLIMI_DATA").map_or_else(|_| PathBuf::from("./kolimi-data"), PathBuf::from);
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
            remove_passkeys,
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
                remove_passkeys,
            )
            .await?;
            println!(
                "recovered {username}: password set, {} session(s) dropped, TOTP {}, {} passkey(s) removed",
                report.sessions_dropped,
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

async fn group_command(command: GroupCommand) -> Result<(), Box<dyn Error>> {
    let data: PathBuf =
        std::env::var("KOLIMI_DATA").map_or_else(|_| PathBuf::from("./kolimi-data"), PathBuf::from);
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

async fn backup(data: PathBuf, to: PathBuf) -> Result<(), Box<dyn Error>> {
    tokio::fs::create_dir_all(&to).await?;
    let db = kolimi_db::Db::connect(&data.join("kolimi.db")).await?;
    let db_target = to.join("kolimi.db");
    if tokio::fs::try_exists(&db_target).await? {
        tokio::fs::remove_file(&db_target).await?;
    }
    db.backup_to(&db_target).await?;

    let store = kolimi_store::BlobStore::open(data.join("blobs")).await?;
    let blobs = store.copy_tree_to(&to.join("blobs")).await?;
    println!(
        "backup complete: database snapshot + {blobs} blobs written to {}",
        to.display()
    );
    Ok(())
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

async fn audit_command(command: AuditCommand) -> Result<(), Box<dyn Error>> {
    let data: PathBuf =
        std::env::var("KOLIMI_DATA").map_or_else(|_| PathBuf::from("./kolimi-data"), PathBuf::from);
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
        AuditCommand::Verify => {
            let verify = db.audit_verify().await?;
            match verify.first_bad {
                None => println!("audit chain ok ({} entries)", verify.entries),
                Some(id) => {
                    eprintln!(
                        "audit chain BROKEN at entry {id} ({} entries checked)",
                        verify.entries
                    );
                    std::process::exit(1);
                }
            }
        }
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
