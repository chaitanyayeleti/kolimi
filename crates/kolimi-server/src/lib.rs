//! Kolimi server: composition root.
//!
//! Wires the database, blob store, VFS, WebDAV surface, and session API
//! into a single axum application. TLS termination lives in the binary.

pub mod admin;
pub mod api;
pub mod api_2fa;
pub mod api_browse;
pub mod api_e2ee;
pub mod api_passkey;
pub mod api_shares;
pub mod api_sync;
pub mod auth;
pub mod hardening;
pub mod janitor;
pub mod metrics;
pub mod preview;
pub mod search_indexer;
pub mod ui;

use std::{path::Path, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    routing::{any, delete, get, patch, post},
};
use kolimi_auth::{cache::CredentialCache, lockout::FailedAuthTracker, passkey::Passkeys};
use kolimi_db::Db;
use kolimi_search::SearchIndex;
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
/// Maximum concurrent SSE change streams.
pub const SSE_MAX_CONNECTIONS: usize = 64;
/// Lifetime cap for a single SSE change stream.
pub const SSE_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

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
    /// Search index initialization failure.
    #[error("search index: {0}")]
    Search(#[from] kolimi_search::SearchError),
    /// Metrics registration failure.
    #[error("metrics: {0}")]
    Metrics(#[from] prometheus::Error),
}

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Database handle.
    pub db: Arc<Db>,
    /// Virtual filesystem.
    pub vfs: Arc<Vfs>,
    /// WebDAV class-2 lock store.
    pub locks: Arc<kolimi_webdav::LockManager>,
    /// Failed-login tracker.
    pub lockout: Arc<FailedAuthTracker>,
    /// Basic-auth verification cache.
    pub cred_cache: Arc<CredentialCache>,
    /// WebAuthn ceremonies.
    pub passkeys: Arc<Passkeys>,
    /// Full-text search index.
    pub search: Arc<SearchIndex>,
    /// Whether to set the `Secure` attribute on cookies.
    pub secure_cookies: bool,
    /// Data directory (used for preview scratch files).
    pub data_dir: PathBuf,
    /// Executable that serves as the sandboxed preview worker.
    pub preview_worker: PathBuf,
    /// Limits concurrent preview workers.
    pub preview_permits: Arc<tokio::sync::Semaphore>,
    /// Caps concurrent SSE change streams.
    pub sse_permits: Arc<tokio::sync::Semaphore>,
    /// Prometheus metrics.
    pub metrics: Arc<metrics::Metrics>,
    /// Per-client rate limiter for sensitive endpoints.
    pub rate_limiter: Arc<hardening::RateLimiter>,
    /// Fixed password hash verified when a user has none, so login timing
    /// does not reveal whether a username exists (see issue about
    /// enumeration).
    pub dummy_password_hash: String,
    /// Whether to read the client address from `X-Forwarded-For`
    /// (`KOLIMI_TRUST_PROXY=1` when behind a trusted reverse proxy).
    pub trust_proxy: bool,
}

impl AppState {
    /// Opens or creates the data directory and all subsystems.
    pub async fn init(
        data_dir: &Path,
        secure_cookies: bool,
        origin: &str,
    ) -> Result<Self, InitError> {
        tokio::fs::create_dir_all(data_dir).await?;
        tokio::fs::create_dir_all(data_dir.join("tmp")).await?;
        let db = Db::connect(&data_dir.join("kolimi.db")).await?;
        let quota_bytes = std::env::var("KOLIMI_USER_QUOTA_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let store = BlobStore::open_with_quota(data_dir.join("blobs"), quota_bytes).await?;
        let vfs = Arc::new(Vfs::new(db.clone(), store));
        let search = Arc::new(SearchIndex::open(&data_dir.join("search"))?);
        // Repair window: an account deleted via the CLI while the server was
        // running could not lock the index, so its search documents leak.
        // Prune them at startup (also closes the SQLite row-id-reuse hole).
        match db.list_users().await {
            Ok(users) => {
                let live: std::collections::HashSet<i64> =
                    users.iter().map(|user| user.id).collect();
                match search.prune_missing_users(&live) {
                    Ok(0) => {}
                    Ok(pruned) => {
                        if let Err(error) = search.commit() {
                            tracing::warn!(%error, "could not commit search orphan prune");
                        } else {
                            tracing::info!(pruned, "pruned search documents of deleted users");
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "could not prune search documents of deleted users");
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "could not list users for search orphan prune");
            }
        }
        let preview_worker =
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("kolimi-server"));
        let dummy_password_hash =
            kolimi_auth::password::hash_password("kolimi-dummy-hash-please-ignore")?;
        let trust_proxy = matches!(
            std::env::var("KOLIMI_TRUST_PROXY").ok().as_deref(),
            Some("1" | "true" | "yes" | "on")
        );
        Ok(Self {
            db: Arc::new(db),
            vfs,
            locks: Arc::new(kolimi_webdav::LockManager::new()),
            lockout: Arc::new(FailedAuthTracker::new(
                MAX_FAILED_LOGINS,
                LOGIN_WINDOW,
                LOGIN_LOCKOUT,
            )),
            cred_cache: Arc::new(CredentialCache::new(Duration::from_secs(60), 1024)),
            passkeys: Arc::new(Passkeys::from_origin(origin, "Kolimi")?),
            search,
            secure_cookies,
            data_dir: data_dir.to_path_buf(),
            preview_worker,
            preview_permits: Arc::new(tokio::sync::Semaphore::new(preview::MAX_CONCURRENT_WORKERS)),
            sse_permits: Arc::new(tokio::sync::Semaphore::new(SSE_MAX_CONNECTIONS)),
            metrics: Arc::new(metrics::Metrics::new()?),
            rate_limiter: Arc::new(hardening::RateLimiter::new()),
            dummy_password_hash,
            trust_proxy,
        })
    }
}

/// Builds the full HTTP application.
pub fn build_app(state: AppState) -> Router {
    let protected = Router::new()
        .merge(kolimi_webdav::routes())
        .route("/api/me", get(api::me))
        .route("/api/me/usage", get(api::self_usage))
        .route("/api/session", delete(api::logout))
        .route("/api/users", get(api::list_users).post(api::create_user))
        .route(
            "/api/users/{username}",
            get(api::user_detail)
                .patch(api::update_user)
                .delete(api::delete_user),
        )
        .route("/api/users/{username}/usage", get(api::user_usage))
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
        .route("/api/totp", get(api_2fa::status))
        .route("/api/totp/begin", post(api_2fa::begin))
        .route("/api/totp/enable", post(api_2fa::enable))
        .route("/api/totp/disable", post(api_2fa::disable))
        .route(
            "/api/e2ee/keyring",
            get(api_e2ee::get_keyring).put(api_e2ee::put_keyring),
        )
        .route(
            "/api/files/key",
            get(api_e2ee::get_file_key).put(api_e2ee::put_file_key),
        )
        .route(
            "/api/e2ee/identity",
            get(api_e2ee::get_identity).put(api_e2ee::put_identity),
        )
        .route(
            "/api/e2ee/identity/{username}",
            get(api_e2ee::public_identity),
        )
        .route(
            "/api/e2ee/share-key",
            get(api_e2ee::get_share_key).put(api_e2ee::put_share_key),
        )
        .route(
            "/api/e2ee/enrollments",
            get(api_e2ee::list_enrollments).post(api_e2ee::create_enrollment),
        )
        .route(
            "/api/e2ee/enrollments/{id}",
            get(api_e2ee::get_enrollment).delete(api_e2ee::delete_enrollment),
        )
        .route(
            "/api/e2ee/enrollments/{id}/approve",
            post(api_e2ee::approve_enrollment),
        )
        .route("/api/e2ee/devices", get(api_e2ee::list_devices))
        .route("/api/e2ee/devices/{id}", delete(api_e2ee::delete_device))
        .route("/api/sync/shared-tree", get(api_sync::shared_tree))
        .route("/api/files", axum::routing::put(api_sync::commit_file))
        .route("/api/chunks/exist", post(api_sync::chunks_exist))
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
        .route("/api/browse", get(api_browse::browse))
        .route("/api/files/info", get(api_browse::info))
        .route("/api/files/move", post(api_browse::move_node))
        .route("/api/search", get(api::search))
        .route("/api/preview", get(preview::handler))
        .route(
            "/api/shares",
            get(api_shares::list).post(api_shares::create),
        )
        .route("/api/shares/received", get(api_shares::received))
        .route("/api/shares/owned", get(api_shares::owned))
        .route(
            "/api/shares/{id}",
            patch(api_shares::update).delete(api_shares::delete),
        )
        .route("/api/shareable", get(api_shares::shareable))
        .route("/api/groups/{name}/members", get(api_shares::group_members))
        // Admin-only; the handler checks is_admin (401 when anonymous).
        .route("/metrics", get(metrics::handler))
        // Requires authentication so the exact version is not public.
        .route("/version", get(api::version))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    let public = Router::new()
        .route("/healthz", get(api::healthz))
        .route("/", get(ui::root))
        .route("/.well-known/caldav", any(ui::well_known))
        .route("/.well-known/carddav", any(ui::well_known))
        .route("/app", get(ui::index))
        .route("/app/", get(ui::index))
        .route("/app/{*path}", get(ui::asset))
        .route("/s/{token}", get(ui::public_page))
        .route("/api/session", post(api::login))
        .route("/api/passkeys/login/begin", post(api_passkey::login_begin))
        .route(
            "/api/passkeys/login/finish",
            post(api_passkey::login_finish),
        )
        .route("/public/{token}", get(api_shares::public_meta))
        .route("/public/{token}/unlock", post(api_shares::public_unlock))
        .route("/public/{token}/list", get(api_shares::public_list_root))
        .route("/public/{token}/list/{*path}", get(api_shares::public_list))
        .route(
            "/public/{token}/download",
            get(api_shares::public_download_root),
        )
        .route(
            "/public/{token}/download/{*path}",
            get(api_shares::public_download),
        );

    let vfs = state.vfs.clone();
    let locks = state.locks.clone();
    let metrics_state = state.clone();
    Router::new()
        .merge(public)
        .merge(protected)
        .layer(axum::middleware::from_fn_with_state(
            metrics_state,
            metrics::record,
        ))
        .layer(Extension(vfs))
        .layer(Extension(locks))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            hardening::limit,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            hardening::security_headers,
        ))
        .with_state(state)
}

/// Best-effort audit append for request handlers: failures are logged but
/// never fail the audited operation. Use [`kolimi_db::Db::audit_append`]
/// directly where the append must abort the operation.
pub async fn audit(
    state: &AppState,
    actor_id: Option<i64>,
    actor: Option<&str>,
    action: &str,
    subject: &str,
    details: serde_json::Value,
) {
    if let Err(error) = state
        .db
        .audit_append(actor_id, actor, action, subject, &details)
        .await
    {
        tracing::error!(%error, action, subject, "audit append failed");
    }
}
