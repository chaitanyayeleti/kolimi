//! Prometheus metrics.
//!
//! Deliberately small and content-free: request counts and latencies by
//! route template, plus a handful of application counters. No file
//! names, paths, or user identifiers are ever labeled.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Extension, MatchedPath, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{
    Counter, Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};
use serde::Deserialize;

use kolimi_auth::CurrentUser;
use kolimi_db::{MetricsSnapshot, User};

use crate::AppState;

/// Registry and counters for one server process.
#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    requests: IntCounterVec,
    duration: HistogramVec,
    request_bytes: IntCounterVec,
    response_bytes: IntCounterVec,
    in_flight: IntGauge,
    uploads: IntCounter,
    upload_bytes: IntCounter,
    download_bytes: IntCounter,
    chunk_upload_bytes: IntCounter,
    chunk_download_bytes: IntCounter,
    previews: IntCounterVec,
    preview_duration: HistogramVec,
    login_failures: IntCounter,
    logins: IntCounterVec,
    auth_touches: IntCounterVec,
    browse_page_entries: Histogram,
    browse_pages: IntCounterVec,
    db_write_transactions: IntCounter,
    db_audit_entries: IntCounter,
    db_change_events: IntCounter,
    indexer_runs: IntCounterVec,
    indexer_documents: IntCounterVec,
    indexer_duration: HistogramVec,
    usage_bucket: IntGaugeVec,
    users_total: IntGaugeVec,
    users_mfa_pending: IntGauge,
    storage_used_bytes: IntGauge,
    user_used: IntGaugeVec,
    sessions_active: IntGauge,
    app_passwords_active: IntGauge,
    mls_devices: IntGauge,
    mls_key_packages: IntGauge,
    files_total: IntGauge,
    trash_nodes: IntGauge,
    versions_total: IntGauge,
    db_pool: IntGaugeVec,
    sse_active: IntGauge,
    sse_rejected: IntCounter,
    rate_limited: IntCounterVec,
    mls_commits: IntCounterVec,
    janitor_runs: IntCounterVec,
    janitor_duration: HistogramVec,
    janitor_events: IntCounterVec,
    janitor_last_success: IntGauge,
    audit_checkpoints_signed: IntCounter,
    audit_signing_errors: IntCounter,
    audit_anchor_pending: IntGauge,
    audit_anchor_delivered: IntCounterVec,
    audit_anchor_failures: IntCounterVec,
    process_rss: IntGauge,
    process_threads: IntGauge,
    process_fds: IntGauge,
    process_cpu: Counter,
    db_errors: IntCounter,
    db_busy_errors: IntCounter,
    last_db_errors: Arc<Mutex<u64>>,
    last_db_busy_errors: Arc<Mutex<u64>>,
    last_db_write_transactions: Arc<Mutex<u64>>,
    last_db_audit_entries: Arc<Mutex<u64>>,
    last_db_change_events: Arc<Mutex<u64>>,
    last_process_cpu: Arc<Mutex<f64>>,
    per_user_usage: bool,
    last_usage_refresh: Arc<Mutex<Option<Instant>>>,
    usage_refreshing: Arc<AtomicBool>,
}

/// How often the user/quota gauges are rebuilt from the database.
const USAGE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

impl Metrics {
    /// Creates the registry and registers all metrics.
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let requests = IntCounterVec::new(
            Opts::new(
                "kolimi_http_requests_total",
                "HTTP requests by route and status",
            ),
            &["method", "path", "status"],
        )?;
        let duration = HistogramVec::new(
            HistogramOpts::new(
                "kolimi_http_request_duration_seconds",
                "HTTP request latency by route",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
            ]),
            &["method", "path"],
        )?;
        let request_bytes = IntCounterVec::new(
            Opts::new(
                "kolimi_http_request_body_bytes_total",
                "Declared HTTP request body bytes by route",
            ),
            &["method", "path"],
        )?;
        let response_bytes = IntCounterVec::new(
            Opts::new(
                "kolimi_http_response_body_bytes_total",
                "Declared HTTP response body bytes by route",
            ),
            &["method", "path"],
        )?;
        let in_flight = IntGauge::new(
            "kolimi_http_requests_in_flight",
            "Requests currently being handled",
        )?;
        let uploads = IntCounter::new(
            "kolimi_file_uploads_total",
            "Client manifest commits that created a new file version",
        )?;
        let upload_bytes = IntCounter::new(
            "kolimi_file_upload_bytes_total",
            "Logical file bytes committed by clients",
        )?;
        let download_bytes = IntCounter::new(
            "kolimi_file_download_bytes_total",
            "Logical file bytes sent to clients (API and public links)",
        )?;
        let chunk_upload_bytes = IntCounter::new(
            "kolimi_chunk_upload_bytes_total",
            "Chunk bytes received from clients",
        )?;
        let chunk_download_bytes = IntCounter::new(
            "kolimi_chunk_download_bytes_total",
            "Chunk bytes sent to clients",
        )?;
        let previews = IntCounterVec::new(
            Opts::new("kolimi_preview_runs_total", "Preview worker outcomes"),
            &["outcome"],
        )?;
        let preview_duration = HistogramVec::new(
            HistogramOpts::new(
                "kolimi_preview_duration_seconds",
                "Preview worker duration by outcome",
            )
            .buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["outcome"],
        )?;
        let login_failures = IntCounter::new(
            "kolimi_login_failures_total",
            "Rejected password or second-factor attempts",
        )?;
        let logins = IntCounterVec::new(
            Opts::new(
                "kolimi_logins_total",
                "Successful and challenged login outcomes (no user labels)",
            ),
            &["outcome"],
        )?;
        let auth_touches = IntCounterVec::new(
            Opts::new(
                "kolimi_auth_timestamp_writes_total",
                "Credential timestamp refreshes, written or skipped by the minute throttle",
            ),
            &["credential", "result"],
        )?;
        let browse_page_entries = Histogram::with_opts(
            HistogramOpts::new(
                "kolimi_browse_page_entries",
                "Entries returned per /api/browse response",
            )
            .buckets(vec![
                0.0, 1.0, 10.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
            ]),
        )?;
        let browse_pages = IntCounterVec::new(
            Opts::new(
                "kolimi_browse_pages_total",
                "Directory pages served, split by whether another page exists",
            ),
            &["has_more"],
        )?;
        let db_write_transactions = IntCounter::new(
            "kolimi_db_write_transactions_total",
            "Cumulative SQLite write transactions begun by this process",
        )?;
        let db_audit_entries = IntCounter::new(
            "kolimi_audit_entries_appended_total",
            "Cumulative audit rows appended by this process",
        )?;
        let db_change_events = IntCounter::new(
            "kolimi_change_events_appended_total",
            "Cumulative change-feed rows appended by this process",
        )?;
        let indexer_runs = IntCounterVec::new(
            Opts::new("kolimi_indexer_runs_total", "Search indexer pass results"),
            &["result"],
        )?;
        let indexer_documents = IntCounterVec::new(
            Opts::new(
                "kolimi_indexer_documents_total",
                "Documents indexed or removed by the search indexer",
            ),
            &["outcome"],
        )?;
        let indexer_duration = HistogramVec::new(
            HistogramOpts::new(
                "kolimi_indexer_duration_seconds",
                "Search indexer pass duration by result",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 15.0, 60.0]),
            &["result"],
        )?;
        let usage_bucket = IntGaugeVec::new(
            Opts::new(
                "kolimi_users_by_usage_bucket",
                "Accounts by how full their quota is (low cardinality)",
            ),
            &["bucket"],
        )?;
        let users_total = IntGaugeVec::new(
            Opts::new("kolimi_users_total", "Accounts by enabled/disabled state"),
            &["state"],
        )?;
        let users_mfa_pending = IntGauge::new(
            "kolimi_users_mfa_pending",
            "Accounts that still must enroll TOTP or a passkey",
        )?;
        let storage_used_bytes = IntGauge::new(
            "kolimi_storage_used_bytes",
            "Sum of cached per-account used bytes",
        )?;
        let user_used = IntGaugeVec::new(
            Opts::new(
                "kolimi_user_used_bytes",
                "Per-user used storage bytes (opt-in: KOLIMI_METRICS_PER_USER=1)",
            ),
            &["user"],
        )?;
        let sessions_active =
            IntGauge::new("kolimi_sessions_active", "Live, unexpired web sessions")?;
        let app_passwords_active = IntGauge::new(
            "kolimi_app_passwords_active",
            "Stored per-device app passwords",
        )?;
        let mls_devices = IntGauge::new("kolimi_mls_devices", "MLS device-roster entries")?;
        let mls_key_packages = IntGauge::new(
            "kolimi_mls_key_packages",
            "Live, unconsumed MLS key packages",
        )?;
        let files_total = IntGauge::new("kolimi_files", "Live files (excluding trash)")?;
        let trash_nodes = IntGauge::new("kolimi_trash_nodes", "Nodes currently in trash")?;
        let versions_total = IntGauge::new("kolimi_file_versions", "Stored file versions")?;
        let db_pool = IntGaugeVec::new(
            Opts::new(
                "kolimi_db_pool_connections",
                "SQLite pool connections by state",
            ),
            &["state"],
        )?;
        let sse_active = IntGauge::new(
            "kolimi_sse_connections_active",
            "Open sync event-stream connections",
        )?;
        let sse_rejected = IntCounter::new(
            "kolimi_sse_connections_rejected_total",
            "Event streams refused because the connection cap was reached",
        )?;
        let rate_limited = IntCounterVec::new(
            Opts::new(
                "kolimi_rate_limited_total",
                "Requests rejected by the per-client rate limiter",
            ),
            &["surface"],
        )?;
        let mls_commits = IntCounterVec::new(
            Opts::new("kolimi_mls_commits_total", "MLS commit results"),
            &["result"],
        )?;
        let janitor_runs = IntCounterVec::new(
            Opts::new("kolimi_janitor_runs_total", "Janitor pass results"),
            &["result"],
        )?;
        let janitor_duration = HistogramVec::new(
            HistogramOpts::new(
                "kolimi_janitor_duration_seconds",
                "Janitor pass duration by result",
            )
            .buckets(vec![0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0]),
            &["result"],
        )?;
        let janitor_events = IntCounterVec::new(
            Opts::new(
                "kolimi_janitor_events_total",
                "Objects processed by the janitor, by kind",
            ),
            &["kind"],
        )?;
        let janitor_last_success = IntGauge::new(
            "kolimi_janitor_last_success_timestamp_seconds",
            "Unix time of the last successful janitor pass",
        )?;
        let audit_checkpoints_signed = IntCounter::new(
            "kolimi_audit_checkpoints_signed_total",
            "Audit checkpoints sealed with a signature",
        )?;
        let audit_signing_errors = IntCounter::new(
            "kolimi_audit_signing_errors_total",
            "Audit checkpoint sealing failures caused by signing",
        )?;
        let audit_anchor_pending = IntGauge::new(
            "kolimi_audit_anchor_pending",
            "Checkpoint anchors still waiting for a configured sink",
        )?;
        let audit_anchor_delivered = IntCounterVec::new(
            Opts::new(
                "kolimi_audit_anchor_delivered_total",
                "Checkpoint anchors delivered, by sink",
            ),
            &["sink"],
        )?;
        let audit_anchor_failures = IntCounterVec::new(
            Opts::new(
                "kolimi_audit_anchor_failures_total",
                "Checkpoint anchor delivery failures, by sink",
            ),
            &["sink"],
        )?;
        let process_rss = IntGauge::new(
            "kolimi_process_resident_memory_bytes",
            "Resident memory of the server process (Linux)",
        )?;
        let process_threads = IntGauge::new(
            "kolimi_process_threads",
            "Threads in the server process (Linux)",
        )?;
        let process_fds = IntGauge::new(
            "kolimi_process_open_fds",
            "Open file descriptors in the server process (Linux)",
        )?;
        let process_cpu = Counter::new(
            "kolimi_process_cpu_seconds_total",
            "Cumulative CPU time used by the server process (Linux)",
        )?;
        let db_errors = IntCounter::new(
            "kolimi_db_errors_total",
            "Cumulative SQLite query errors observed by this process",
        )?;
        let db_busy_errors = IntCounter::new(
            "kolimi_db_busy_errors_total",
            "Cumulative SQLite SQLITE_BUSY or SQLITE_LOCKED errors",
        )?;
        let start_time = IntGauge::new(
            "kolimi_start_time_seconds",
            "Unix time when this server process started",
        )?;
        let build_info = IntGaugeVec::new(
            Opts::new("kolimi_build_info", "Build metadata (value is always 1)"),
            &["version"],
        )?;
        registry.register(Box::new(requests.clone()))?;
        registry.register(Box::new(duration.clone()))?;
        registry.register(Box::new(request_bytes.clone()))?;
        registry.register(Box::new(response_bytes.clone()))?;
        registry.register(Box::new(in_flight.clone()))?;
        registry.register(Box::new(uploads.clone()))?;
        registry.register(Box::new(upload_bytes.clone()))?;
        registry.register(Box::new(download_bytes.clone()))?;
        registry.register(Box::new(chunk_upload_bytes.clone()))?;
        registry.register(Box::new(chunk_download_bytes.clone()))?;
        registry.register(Box::new(previews.clone()))?;
        registry.register(Box::new(preview_duration.clone()))?;
        registry.register(Box::new(login_failures.clone()))?;
        registry.register(Box::new(logins.clone()))?;
        registry.register(Box::new(auth_touches.clone()))?;
        registry.register(Box::new(browse_page_entries.clone()))?;
        registry.register(Box::new(browse_pages.clone()))?;
        registry.register(Box::new(db_write_transactions.clone()))?;
        registry.register(Box::new(db_audit_entries.clone()))?;
        registry.register(Box::new(db_change_events.clone()))?;
        registry.register(Box::new(indexer_runs.clone()))?;
        registry.register(Box::new(indexer_documents.clone()))?;
        registry.register(Box::new(indexer_duration.clone()))?;
        registry.register(Box::new(usage_bucket.clone()))?;
        registry.register(Box::new(users_total.clone()))?;
        registry.register(Box::new(users_mfa_pending.clone()))?;
        registry.register(Box::new(storage_used_bytes.clone()))?;
        registry.register(Box::new(user_used.clone()))?;
        registry.register(Box::new(sessions_active.clone()))?;
        registry.register(Box::new(app_passwords_active.clone()))?;
        registry.register(Box::new(mls_devices.clone()))?;
        registry.register(Box::new(mls_key_packages.clone()))?;
        registry.register(Box::new(files_total.clone()))?;
        registry.register(Box::new(trash_nodes.clone()))?;
        registry.register(Box::new(versions_total.clone()))?;
        registry.register(Box::new(db_pool.clone()))?;
        registry.register(Box::new(sse_active.clone()))?;
        registry.register(Box::new(sse_rejected.clone()))?;
        registry.register(Box::new(rate_limited.clone()))?;
        registry.register(Box::new(mls_commits.clone()))?;
        registry.register(Box::new(janitor_runs.clone()))?;
        registry.register(Box::new(janitor_duration.clone()))?;
        registry.register(Box::new(janitor_events.clone()))?;
        registry.register(Box::new(janitor_last_success.clone()))?;
        registry.register(Box::new(audit_checkpoints_signed.clone()))?;
        registry.register(Box::new(audit_signing_errors.clone()))?;
        registry.register(Box::new(audit_anchor_pending.clone()))?;
        registry.register(Box::new(audit_anchor_delivered.clone()))?;
        registry.register(Box::new(audit_anchor_failures.clone()))?;
        registry.register(Box::new(process_rss.clone()))?;
        registry.register(Box::new(process_threads.clone()))?;
        registry.register(Box::new(process_fds.clone()))?;
        registry.register(Box::new(process_cpu.clone()))?;
        registry.register(Box::new(db_errors.clone()))?;
        registry.register(Box::new(db_busy_errors.clone()))?;
        registry.register(Box::new(start_time.clone()))?;
        registry.register(Box::new(build_info.clone()))?;
        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1);
        start_time.set(unix_seconds());
        // Create zero-valued children for low-cardinality vectors so
        // dashboards see a stable family before the first event.
        for result in ["success", "error"] {
            indexer_runs.with_label_values(&[result]);
        }
        for outcome in ["indexed", "removed"] {
            indexer_documents.with_label_values(&[outcome]);
        }
        for credential in ["session", "app_password"] {
            for result in ["written", "skipped", "error"] {
                auth_touches.with_label_values(&[credential, result]);
            }
        }
        for has_more in ["true", "false"] {
            browse_pages.with_label_values(&[has_more]);
        }
        Ok(Self {
            registry,
            requests,
            duration,
            request_bytes,
            response_bytes,
            in_flight,
            uploads,
            upload_bytes,
            download_bytes,
            chunk_upload_bytes,
            chunk_download_bytes,
            previews,
            preview_duration,
            login_failures,
            logins,
            auth_touches,
            browse_page_entries,
            browse_pages,
            db_write_transactions,
            db_audit_entries,
            db_change_events,
            indexer_runs,
            indexer_documents,
            indexer_duration,
            usage_bucket,
            users_total,
            users_mfa_pending,
            storage_used_bytes,
            user_used,
            sessions_active,
            app_passwords_active,
            mls_devices,
            mls_key_packages,
            files_total,
            trash_nodes,
            versions_total,
            db_pool,
            sse_active,
            sse_rejected,
            rate_limited,
            mls_commits,
            janitor_runs,
            janitor_duration,
            janitor_events,
            janitor_last_success,
            audit_checkpoints_signed,
            audit_signing_errors,
            audit_anchor_pending,
            audit_anchor_delivered,
            audit_anchor_failures,
            process_rss,
            process_threads,
            process_fds,
            process_cpu,
            db_errors,
            db_busy_errors,
            last_db_errors: Arc::new(Mutex::new(0)),
            last_db_busy_errors: Arc::new(Mutex::new(0)),
            last_db_write_transactions: Arc::new(Mutex::new(0)),
            last_db_audit_entries: Arc::new(Mutex::new(0)),
            last_db_change_events: Arc::new(Mutex::new(0)),
            last_process_cpu: Arc::new(Mutex::new(0.0)),
            per_user_usage: std::env::var("KOLIMI_METRICS_PER_USER")
                .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes")),
            last_usage_refresh: Arc::new(Mutex::new(None)),
            usage_refreshing: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Whether the cached quota/user gauges are due for a refresh.
    pub fn usage_refresh_due(&self) -> bool {
        let last = self
            .last_usage_refresh
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *last {
            None => true,
            Some(at) => at.elapsed() >= USAGE_REFRESH_INTERVAL,
        }
    }

    /// Claims the usage-refresh slot. Returns false when another scrape is
    /// already refreshing or the cache is still fresh.
    pub fn try_begin_usage_refresh(&self) -> bool {
        if !self.usage_refresh_due() {
            return false;
        }
        !self.usage_refreshing.swap(true, Ordering::AcqRel)
    }

    /// Marks a successful usage refresh.
    pub fn finish_usage_refresh(&self) {
        let mut last = self
            .last_usage_refresh
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *last = Some(Instant::now());
        self.usage_refreshing.store(false, Ordering::Release);
    }

    /// Releases a failed refresh so the next scrape can retry.
    pub fn abort_usage_refresh(&self) {
        self.usage_refreshing.store(false, Ordering::Release);
    }

    /// Refreshes the quota-usage gauges from the account list.
    ///
    /// Bucketed counts are always updated (low cardinality). Per-user
    /// gauges are only set when `KOLIMI_METRICS_PER_USER` is enabled, to
    /// avoid unbounded label cardinality on large instances.
    pub fn refresh_user_usage(&self, users: &[User], default_quota: u64) {
        use std::collections::HashMap;

        let mut counts: HashMap<&str, i64> = HashMap::new();
        for bucket in ["0", "1-50", "50-90", "90-100", "over", "unlimited"] {
            counts.insert(bucket, 0);
        }
        if self.per_user_usage {
            self.user_used.reset();
        }
        let (mut enabled, mut disabled, mut mfa_pending, mut stored) = (0i64, 0i64, 0i64, 0i64);
        for account in users {
            let quota = match account.quota_bytes {
                Some(q) if q > 0 => q as u64,
                Some(_) => 0,
                None => default_quota,
            };
            let used = account.used_bytes.max(0) as u64;
            let bucket = if quota == 0 {
                "unlimited"
            } else if used >= quota {
                "over"
            } else if used.saturating_mul(100) >= quota.saturating_mul(90) {
                "90-100"
            } else if used.saturating_mul(100) >= quota.saturating_mul(50) {
                "50-90"
            } else if used > 0 {
                "1-50"
            } else {
                "0"
            };
            if let Some(count) = counts.get_mut(bucket) {
                *count += 1;
            }
            if account.disabled {
                disabled += 1;
            } else {
                enabled += 1;
            }
            if account.must_setup_mfa {
                mfa_pending += 1;
            }
            stored = stored.saturating_add(i64::try_from(used).unwrap_or(i64::MAX));
            if self.per_user_usage {
                self.user_used
                    .with_label_values(&[&account.username])
                    .set(used as i64);
            }
        }
        for (bucket, count) in counts {
            self.usage_bucket.with_label_values(&[bucket]).set(count);
        }
        self.users_total
            .with_label_values(&["enabled"])
            .set(enabled);
        self.users_total
            .with_label_values(&["disabled"])
            .set(disabled);
        self.users_mfa_pending.set(mfa_pending);
        self.storage_used_bytes.set(stored);
    }

    /// Copies a database snapshot into the operational gauges.
    pub fn set_snapshot(&self, snapshot: MetricsSnapshot) {
        self.sessions_active.set(snapshot.sessions_active);
        self.app_passwords_active.set(snapshot.app_passwords);
        self.mls_devices.set(snapshot.mls_devices);
        self.mls_key_packages.set(snapshot.mls_key_packages);
        self.files_total.set(snapshot.files);
        self.trash_nodes.set(snapshot.trash);
        self.versions_total.set(snapshot.versions);
    }

    /// Updates SQLite connection-pool gauges.
    pub fn set_pool_stats(&self, size: u32, idle: u32) {
        let size = i64::from(size);
        let idle = i64::from(idle);
        self.db_pool
            .with_label_values(&["in_use"])
            .set((size - idle).max(0));
        self.db_pool.with_label_values(&["idle"]).set(idle);
    }

    /// Updates cumulative SQLite error and write-volume counters from the
    /// database layer.
    pub fn set_db_counters(&self, errors: u64, busy: u64, write_tx: u64, audit: u64, changes: u64) {
        fn bump(counter: &IntCounter, last: &Mutex<u64>, value: u64) {
            let mut last = last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let delta = if value >= *last { value - *last } else { value };
            if delta > 0 {
                counter.inc_by(delta);
            }
            *last = value;
        }
        bump(&self.db_errors, &self.last_db_errors, errors);
        bump(&self.db_busy_errors, &self.last_db_busy_errors, busy);
        bump(
            &self.db_write_transactions,
            &self.last_db_write_transactions,
            write_tx,
        );
        bump(&self.db_audit_entries, &self.last_db_audit_entries, audit);
        bump(&self.db_change_events, &self.last_db_change_events, changes);
    }

    fn set_process_cpu(&self, seconds: f64) {
        let mut last = self
            .last_process_cpu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let delta = if seconds >= *last {
            seconds - *last
        } else {
            seconds
        };
        if delta > 0.0 {
            self.process_cpu.inc_by(delta);
        }
        *last = seconds;
    }

    /// Updates the active SSE-stream gauge from the semaphore.
    pub fn set_sse_active(&self, active: usize) {
        self.sse_active.set(active as i64);
    }

    /// Counts a refused SSE stream.
    pub fn sse_rejected(&self) {
        self.sse_rejected.inc();
    }

    /// Counts a rate-limited request by surface.
    pub fn rate_limited(&self, surface: &str) {
        self.rate_limited.with_label_values(&[surface]).inc();
    }

    /// Counts an MLS commit result (`ok`, `conflict`, `error`).
    pub fn mls_commit(&self, result: &str) {
        self.mls_commits.with_label_values(&[result]).inc();
    }

    /// Counts a credential timestamp refresh (`written`, `skipped`, or
    /// `error`) by the once-per-minute throttle.
    pub fn auth_touch(&self, credential: &str, result: &str) {
        self.auth_touches
            .with_label_values(&[credential, result])
            .inc();
    }

    /// Records one `/api/browse` page and its size.
    pub fn browse_page(&self, entries: usize, has_more: bool) {
        self.browse_page_entries.observe(entries as f64);
        self.browse_pages
            .with_label_values(&[if has_more { "true" } else { "false" }])
            .inc();
    }

    /// Records one search-indexer pass.
    pub fn indexer_pass(&self, result: &str, seconds: f64, indexed: u64, removed: u64) {
        self.indexer_runs.with_label_values(&[result]).inc();
        self.indexer_duration
            .with_label_values(&[result])
            .observe(seconds);
        if indexed > 0 {
            self.indexer_documents
                .with_label_values(&["indexed"])
                .inc_by(indexed);
        }
        if removed > 0 {
            self.indexer_documents
                .with_label_values(&["removed"])
                .inc_by(removed);
        }
    }

    /// Records one janitor pass.
    pub fn janitor_pass(&self, result: &str, seconds: f64) {
        self.janitor_runs.with_label_values(&[result]).inc();
        self.janitor_duration
            .with_label_values(&[result])
            .observe(seconds);
        if result == "success" {
            self.janitor_last_success.set(unix_seconds());
        }
    }

    /// Adds a janitor event count.
    pub fn janitor_event(&self, kind: &str, count: u64) {
        if count > 0 {
            self.janitor_events.with_label_values(&[kind]).inc_by(count);
        }
    }

    /// Records signed audit checkpoints.
    pub fn audit_checkpoints_signed(&self, count: u64) {
        if count > 0 {
            self.audit_checkpoints_signed.inc_by(count);
        }
    }

    /// Records an audit-signing failure.
    pub fn audit_signing_error(&self) {
        self.audit_signing_errors.inc();
    }

    /// Sets the pending-anchor gauge.
    pub fn set_audit_anchor_pending(&self, pending: i64) {
        self.audit_anchor_pending.set(pending);
    }

    /// Records delivered anchor records for one sink.
    pub fn audit_anchor_delivered(&self, sink: &str, count: u64) {
        if count > 0 {
            self.audit_anchor_delivered
                .with_label_values(&[sink])
                .inc_by(count);
        }
    }

    /// Records an anchor delivery failure for one sink.
    pub fn audit_anchor_failure(&self, sink: &str) {
        self.audit_anchor_failures.with_label_values(&[sink]).inc();
    }

    fn observe(
        &self,
        method: &str,
        path: &str,
        status: u16,
        seconds: f64,
        request_bytes: u64,
        response_bytes: u64,
    ) {
        self.requests
            .with_label_values(&[method, path, &status.to_string()])
            .inc();
        self.duration
            .with_label_values(&[method, path])
            .observe(seconds);
        if request_bytes > 0 {
            self.request_bytes
                .with_label_values(&[method, path])
                .inc_by(request_bytes);
        }
        if response_bytes > 0 {
            self.response_bytes
                .with_label_values(&[method, path])
                .inc_by(response_bytes);
        }
    }

    /// Counts a committed upload and its logical bytes.
    pub fn upload(&self, bytes: u64) {
        self.uploads.inc();
        self.upload_bytes.inc_by(bytes);
    }

    /// Counts logical file bytes sent to a client.
    pub fn download(&self, bytes: u64) {
        self.download_bytes.inc_by(bytes);
    }

    /// Counts chunk bytes received from a client.
    pub fn chunk_upload(&self, bytes: u64) {
        self.chunk_upload_bytes.inc_by(bytes);
    }

    /// Counts chunk bytes sent to a client.
    pub fn chunk_download(&self, bytes: u64) {
        self.chunk_download_bytes.inc_by(bytes);
    }

    /// Counts a preview worker outcome and duration.
    pub fn preview(&self, outcome: &str, seconds: f64) {
        self.previews.with_label_values(&[outcome]).inc();
        self.preview_duration
            .with_label_values(&[outcome])
            .observe(seconds);
    }

    /// Counts a rejected login (bad password, TOTP, or recovery code).
    pub fn login_failure(&self) {
        self.login_failures.inc();
        self.login("failure");
    }

    /// Counts a login outcome (`password`, `totp`, `recovery`, `passkey`,
    /// `totp_required`, `failure`).
    pub fn login(&self, outcome: &str) {
        self.logins.with_label_values(&[outcome]).inc();
    }

    /// Refreshes Linux process gauges before a render.
    fn refresh_process_metrics(&self) {
        if let Some(kb) = proc_status_value("VmRSS") {
            self.process_rss.set(kb.saturating_mul(1024));
        }
        if let Some(threads) = proc_status_value("Threads") {
            self.process_threads.set(threads);
        }
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            self.process_fds.set(entries.count() as i64);
        }
        if let Some(seconds) = process_cpu_seconds() {
            self.set_process_cpu(seconds);
        }
    }

    fn try_render(&self) -> Result<String, String> {
        self.refresh_process_metrics();
        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buffer)
            .map_err(|error| error.to_string())?;
        String::from_utf8(buffer).map_err(|error| error.to_string())
    }

    /// Renders the Prometheus text exposition format.
    pub fn render(&self) -> String {
        self.try_render().unwrap_or_default()
    }

    /// Renders the same registry as a small self-contained HTML dashboard
    /// for humans browsing `/metrics`. Scrapers still get the text format
    /// via content negotiation in `handler`.
    ///
    /// Parses the text exposition rather than the protobuf registry so it
    /// stays stable across `prometheus`/`protobuf` API changes.
    pub fn render_html(&self) -> Result<String, String> {
        let text = self.try_render()?;
        let mut out = String::new();
        let mut section: Option<(String, String, String, String)> = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# HELP ") {
                if let Some(parts) = section.take() {
                    out.push_str(&render_section(&parts.0, &parts.1, &parts.2, &parts.3));
                }
                let (name, help) = rest.split_once(' ').unwrap_or((rest, ""));
                section = Some((
                    name.to_string(),
                    help.to_string(),
                    String::new(),
                    String::new(),
                ));
            } else if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (_, kind) = rest.split_once(' ').unwrap_or((rest, ""));
                if let Some(current) = section.as_mut() {
                    current.2 = kind.to_string();
                }
            } else if line.starts_with('#') || line.trim().is_empty() {
                continue;
            } else if let Some((metric, value)) = line.rsplit_once(' ')
                && let Some(current) = section.as_mut()
            {
                let labels = match metric.split_once('{') {
                    Some((_, rest)) => format!("{{{rest}"),
                    None => "—".to_string(),
                };
                push_row(&mut current.3, &escape(&labels), value);
            }
        }
        if let Some(parts) = section {
            out.push_str(&render_section(&parts.0, &parts.1, &parts.2, &parts.3));
        }
        Ok(format!("{HTML_HEAD}{out}{HTML_TAIL}"))
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn proc_status_value(name: &str) -> Option<i64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key != name {
            return None;
        }
        value.split_whitespace().next()?.parse().ok()
    })
}

/// Linux reports CPU time in `USER_HZ` ticks, which is 100 on normal
/// configurations. This is a metrics-only approximation; it never drives
/// scheduling or billing.
fn process_cpu_seconds() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let (_, rest) = stat.rsplit_once(')')?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let user: f64 = fields.get(11)?.parse().ok()?;
    let system: f64 = fields.get(12)?.parse().ok()?;
    Some((user + system) / 100.0)
}

/// Renders one metric family as an HTML card.
fn render_section(name: &str, help: &str, kind: &str, rows: &str) -> String {
    let mut out = String::from("<section class=\"metric\"><h2>");
    out.push_str(&escape(name));
    if !kind.is_empty() {
        out.push_str(" <span class=\"kind\">");
        out.push_str(&escape(kind));
        out.push_str("</span>");
    }
    out.push_str("</h2>");
    if !help.is_empty() {
        out.push_str("<p class=\"help\">");
        out.push_str(&escape(help));
        out.push_str("</p>");
    }
    out.push_str("<table><thead><tr><th>labels</th><th>value</th></tr></thead><tbody>");
    out.push_str(rows);
    out.push_str("</tbody></table></section>");
    out
}

fn push_row(out: &mut String, labels: &str, value: &str) {
    out.push_str("<tr><td class=\"labels\">");
    out.push_str(labels);
    out.push_str("</td><td class=\"value\">");
    out.push_str(value);
    out.push_str("</td></tr>");
}

/// Minimal HTML escaping for labels and help text.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

const HTML_HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="15">
<title>Kolimi metrics</title>
<style>
:root { color-scheme: light dark; --fg:#1b1b1f; --muted:#6b6b76; --bg:#f7f7f9; --card:#fff; --line:#e3e3e8; --accent:#3b6ef5; }
@media (prefers-color-scheme: dark) { :root { --fg:#e6e6ea; --muted:#9a9aa6; --bg:#141417; --card:#1c1c21; --line:#2b2b33; --accent:#7aa2ff; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
header { padding:24px clamp(16px,4vw,48px) 8px; }
h1 { margin:0 0 4px; font-size:20px; }
header p { margin:0; color:var(--muted); font-size:13px; }
header a { color:var(--accent); }
main { padding:16px clamp(16px,4vw,48px) 48px; display:grid; gap:16px; grid-template-columns:repeat(auto-fill,minmax(360px,1fr)); align-items:start; }
.metric { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }
.metric h2 { margin:0 0 2px; font-size:14px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-word; }
.kind { color:var(--muted); font-weight:400; font-size:11px; text-transform:uppercase; letter-spacing:.04em; }
.help { margin:2px 0 10px; color:var(--muted); font-size:12px; }
table { width:100%; border-collapse:collapse; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
th { text-align:left; color:var(--muted); font-weight:500; border-bottom:1px solid var(--line); padding:4px 6px; }
td { padding:3px 6px; border-bottom:1px solid var(--line); vertical-align:top; }
tr:last-child td { border-bottom:none; }
td.value { text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }
td.labels { color:var(--muted); word-break:break-word; }
</style>
</head>
<body>
<header>
<h1>Kolimi metrics</h1>
<p>Auto-refreshes every 15s · <a href="?format=text">Prometheus text format</a></p>
</header>
<main>"#;

const HTML_TAIL: &str = "</main></body></html>";

/// Middleware: records request counts and latency by route template.
///
/// Unmatched requests (404s) share one fixed label. Labelling them with the
/// raw request path lets an unauthenticated client create unbounded metric
/// series (and a matching Prometheus cardinality explosion).
pub async fn record(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let method = normalize_method(request.method().as_str());
    let request_bytes = content_length(request.headers());
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let started = Instant::now();
    state.metrics.in_flight.inc();
    let response = next.run(request).await;
    state.metrics.in_flight.dec();
    state.metrics.observe(
        method,
        &path,
        response.status().as_u16(),
        started.elapsed().as_secs_f64(),
        request_bytes,
        content_length(response.headers()),
    );
    response
}

/// Keeps the `method` label bounded. HTTP permits arbitrary method tokens,
/// and an unauthenticated client must not be able to create metric series by
/// inventing one.
fn normalize_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        "PROPFIND" => "PROPFIND",
        "PROPPATCH" => "PROPPATCH",
        "MKCOL" => "MKCOL",
        "COPY" => "COPY",
        "MOVE" => "MOVE",
        "LOCK" => "LOCK",
        "UNLOCK" => "UNLOCK",
        "REPORT" => "REPORT",
        _ => "other",
    }
}

fn content_length(headers: &HeaderMap) -> u64 {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Query for `GET /metrics`.
#[derive(Deserialize)]
pub struct MetricsQuery {
    /// `?format=text` forces the Prometheus text format in a browser.
    #[serde(default)]
    format: Option<String>,
}

/// Whether the client should receive the HTML dashboard.
///
/// Honors `q` values instead of the old substring check, so a scraper that
/// sends `Accept: text/html;q=0.1, text/plain;q=0.9` still gets text.
fn prefers_html(header: Option<&str>) -> bool {
    let Some(header) = header else {
        return false;
    };
    let (mut html, mut plain) = (0.0f32, 0.0f32);
    for part in header.split(',') {
        let mut pieces = part.split(';');
        let media = pieces.next().unwrap_or_default().trim();
        let quality = pieces
            .find_map(|parameter| {
                let parameter = parameter.trim();
                let value = parameter.strip_prefix("q=")?;
                value.parse::<f32>().ok()
            })
            .unwrap_or(1.0);
        match media {
            "text/html" => html = html.max(quality),
            "text/plain" | "*/*" => plain = plain.max(quality),
            _ => {}
        }
    }
    html > plain
}

/// `GET /metrics` — administrators or a valid metrics token.
///
/// Returns the Prometheus text exposition format for scrapers. A browser
/// (which sends `Accept: text/html`) gets a small HTML dashboard instead;
/// `?format=text` forces the text format anywhere.
pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<MetricsQuery>,
    headers: HeaderMap,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    state.metrics.set_sse_active(
        crate::SSE_MAX_CONNECTIONS.saturating_sub(state.sse_permits.available_permits()),
    );
    let (size, idle) = state.db.pool_stats();
    state.metrics.set_pool_stats(size, idle);
    state.metrics.set_db_counters(
        kolimi_db::sqlite_errors(),
        kolimi_db::sqlite_busy_errors(),
        kolimi_db::write_transactions(),
        kolimi_db::audit_entries_appended(),
        kolimi_db::change_events_appended(),
    );
    if state.metrics.try_begin_usage_refresh() {
        match state.db.list_users().await {
            Ok(users) => {
                state
                    .metrics
                    .refresh_user_usage(&users, state.vfs.store().default_quota());
                if let Ok(snapshot) = state.db.metrics_snapshot().await {
                    state.metrics.set_snapshot(snapshot);
                }
                state.metrics.finish_usage_refresh();
            }
            Err(_) => state.metrics.abort_usage_refresh(),
        }
    }
    let wants_html = query.format.as_deref() != Some("text")
        && prefers_html(
            headers
                .get(header::ACCEPT)
                .and_then(|value| value.to_str().ok()),
        );
    let (content_type, body) = if wants_html {
        match state.metrics.render_html() {
            Ok(body) => ("text/html; charset=utf-8", body),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    } else {
        match state.metrics.try_render() {
            Ok(body) => ("text/plain; version=0.0.4", body),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    };
    (
        [
            (header::VARY, "Accept"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_TYPE, content_type),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use kolimi_db::User;

    use super::Metrics;

    fn account(name: &str, used: i64, quota: Option<i64>) -> User {
        User {
            id: 0,
            username: name.to_string(),
            password_hash: String::new(),
            is_admin: false,
            disabled: false,
            created_at: 0,
            last_login_at: None,
            display_name: None,
            email: None,
            must_change_password: false,
            must_setup_mfa: false,
            quota_bytes: quota,
            used_bytes: used,
            usage_updated_at: None,
            credentials_version: 0,
        }
    }

    #[test]
    fn usage_buckets_count_accounts() {
        let metrics = Metrics::new().unwrap();
        let users = vec![
            account("empty", 0, Some(100)),
            account("low", 10, Some(100)),
            account("mid", 60, Some(100)),
            account("near", 95, Some(100)),
            account("over", 150, Some(100)),
            account("unlimited", 500, None),
        ];
        metrics.refresh_user_usage(&users, 0);
        let text = metrics.render();
        assert!(
            text.contains(r#"kolimi_users_by_usage_bucket{bucket="90-100"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"kolimi_users_by_usage_bucket{bucket="over"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"kolimi_users_by_usage_bucket{bucket="unlimited"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"kolimi_users_total{state="enabled"} 6"#),
            "{text}"
        );
    }

    #[test]
    fn method_labels_are_bounded() {
        assert_eq!(super::normalize_method("GET"), "GET");
        assert_eq!(super::normalize_method("PROPFIND"), "PROPFIND");
        assert_eq!(super::normalize_method("FLOOB"), "other");
        assert_eq!(super::normalize_method("get"), "other");
    }

    #[test]
    fn content_negotiation_honors_quality_values() {
        assert!(super::prefers_html(Some("text/html,application/xhtml+xml")));
        assert!(!super::prefers_html(Some("text/plain;version=0.0.4")));
        assert!(!super::prefers_html(Some("*/*")));
        assert!(!super::prefers_html(Some(
            "text/html;q=0.1, text/plain;q=0.9"
        )));
    }

    #[test]
    fn render_html_is_a_result() {
        let metrics = Metrics::new().unwrap();
        let html = metrics.render_html().unwrap();
        assert!(html.contains("kolimi_build_info"), "{html}");
        assert!(html.starts_with("<!doctype html>"), "{html}");
    }
}
