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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        None => serve(cli.serve).await,
        Some(Command::Serve(args)) => serve(args).await,
        Some(Command::User { command }) => user_command(command).await,
    }
}

async fn serve(args: ServeArgs) -> Result<(), Box<dyn Error>> {
    let state = AppState::init(&args.data, args.secure_cookies).await?;
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
                .serve(app.into_make_service())
                .await?;
        }
        (None, None) => {
            if !args.bind.ip().is_loopback() {
                tracing::warn!("TLS is disabled and the listener is not on loopback");
            }
            let listener = tokio::net::TcpListener::bind(args.bind).await?;
            tracing::info!(bind = %args.bind, tls = false, "kolimi server listening");
            axum::serve(listener, app)
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
    let db = kolimi_db::Db::connect(&data.join("kolimi.db")).await?;

    match command {
        UserCommand::Add {
            username,
            admin,
            password,
        } => {
            let password = match password {
                Some(password) => password,
                None => read_password(&format!("Password for {username}: "))?,
            };
            let hash = kolimi_auth::password::hash_password(&password)?;
            let user = db.create_user(&username, &hash).await?;
            if admin && !user.is_admin {
                db.set_admin(user.id, true).await?;
            }
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
            println!("password updated for {username}");
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
