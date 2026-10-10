//! Kolimi server: composition root.
//!
//! Wires the database, blob store, VFS, WebDAV surface, and session API
//! into a single axum application. TLS termination lives in the binary.

pub mod api;
pub mod api_passkey;
pub mod api_sync;
pub mod auth;
pub mod janitor;

use std::{path::Path, sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    routing::{delete, get, post},
};
use kolimi_auth::{cache::CredentialCache, lockout::FailedAuthTracker, passkey::Passkeys};
use kolimi_db::Db;
use kolimi_store::BlobStore;
use kolimi_vfs::Vfs;
use tower_http::trace::TraceLayer;

/// Session cookie name.
pub const SESSION_COOKIE: &str = "kolimi_session";
/// CSRF double-submit cookie name.
pub const CSRF_COOKIE: &str = "kolimi_csrf";
/// Session lifetime in milliseconds (30 days).
pub const SESSION_TTL_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Failed logins allowed per window before lockout.
pub const MAX_FAILED_LOGINS: u32 = 5;
/// Failure counting window.
pub const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Lockout duration after too many failures.
pub const LOGIN_LOCKOUT: Duration = Duration::from_secs(15 * 60);

/// Errors while initializing server state.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// Database failure.
    #[error("database: {0}")]
    Db(#[from] kolimi_db::DbError),
    /// Blob store failure.
    #[error("storage: {0}")]
    Store(#[from] kolimi_store::StoreError),
    /// Filesystem failure creating the data directory.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Passkey relying-party configuration failure.
    #[error("passkey configuration: {0}")]
    Passkey(#[from] kolimi_auth::AuthError),
}

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Database handle.
    pub db: Arc<Db>,
    /// Virtual filesystem.
    pub vfs: Arc<Vfs>,
    /// Failed-login tracker.
    pub lockout: Arc<FailedAuthTracker>,
    /// Basic-auth verification cache.
    pub cred_cache: Arc<CredentialCache>,
    /// WebAuthn ceremonies.
    pub passkeys: Arc<Passkeys>,
    /// Whether to set the `Secure` attribute on cookies.
    pub secure_cookies: bool,
}

impl AppState {
    /// Opens or creates the data directory and all subsystems.
    pub async fn init(
        data_dir: &Path,
        secure_cookies: bool,
        origin: &str,
    ) -> Result<Self, InitError> {
        tokio::fs::create_dir_all(data_dir).await?;
        let db = Db::connect(&data_dir.join("kolimi.db")).await?;
        let store = BlobStore::open(data_dir.join("blobs")).await?;
        let vfs = Arc::new(Vfs::new(db.clone(), store));
        Ok(Self {
            db: Arc::new(db),
            vfs,
            lockout: Arc::new(FailedAuthTracker::new(
                MAX_FAILED_LOGINS,
                LOGIN_WINDOW,
                LOGIN_LOCKOUT,
            )),
            cred_cache: Arc::new(CredentialCache::new(Duration::from_secs(60), 1024)),
            passkeys: Arc::new(Passkeys::from_origin(origin, "Kolimi")?),
            secure_cookies,
        })
    }
}

/// Builds the full HTTP application.
pub fn build_app(state: AppState) -> Router {
    let protected = Router::new()
        .merge(kolimi_webdav::routes())
        .route("/api/me", get(api::me))
        .route("/api/session", delete(api::logout))
        .route("/api/users", post(api::create_user))
        .route("/api/passkeys", get(api_passkey::list))
        .route("/api/passkeys/{id}", delete(api_passkey::delete))
        .route(
            "/api/passkeys/register/begin",
            post(api_passkey::register_begin),
        )
        .route(
            "/api/passkeys/register/finish",
            post(api_passkey::register_finish),
        )
        .route("/api/sync/changes", get(api_sync::changes))
        .route("/api/sync/tree", get(api_sync::tree))
        .route("/api/sync/events", get(api_sync::events))
        .route("/api/manifests/{content_id}", get(api_sync::manifest_by_id))
        .route("/api/files/manifest", get(api_sync::file_manifest))
        .route("/api/files", axum::routing::put(api_sync::commit_file))
        .route(
            "/api/chunks/{hash}",
            get(api_sync::get_chunk).put(api_sync::put_chunk),
        )
        .route("/api/trash", get(api_sync::list_trash))
        .route("/api/trash/{id}", delete(api_sync::delete_trash))
        .route("/api/trash/{id}/restore", post(api_sync::restore_trash))
        .route("/api/versions", get(api_sync::list_versions))
        .route(
            "/api/versions/{id}/restore",
            post(api_sync::restore_version),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    let public = Router::new()
        .route("/healthz", get(api::healthz))
        .route("/version", get(api::version))
        .route("/api/session", post(api::login))
        .route("/api/passkeys/login/begin", post(api_passkey::login_begin))
        .route(
            "/api/passkeys/login/finish",
            post(api_passkey::login_finish),
        );

    let vfs = state.vfs.clone();
    Router::new()
        .merge(public)
        .merge(protected)
        .layer(Extension(vfs))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
