//! External anchoring of signed audit checkpoints (RFC 0014).
//!
//! Anchor records are small, content-free JSON lines. The journal sink
//! appends them to an operator-managed file (ideally WORM or on an
//! independent host); the HTTP sink posts them to a remote store with an
//! idempotency key. Delivery is retried from the durable outbox.

use std::path::{Path, PathBuf};
use std::time::Duration;

use kolimi_db::{AuditAnchorOutboxRow, Db, now_millis};

use crate::metrics::Metrics;

/// Audit anchoring destination configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorConfig {
    /// Append-only JSONL journal path.
    pub journal: Option<PathBuf>,
    /// HTTPS endpoint for anchor records.
    pub url: Option<String>,
    /// Optional bearer token for the HTTP sink.
    pub token: Option<String>,
}

impl AnchorConfig {
    /// Reads `KOLIMI_AUDIT_ANCHOR_*`. Returns `None` when no sink is set.
    pub fn from_env() -> Result<Option<Self>, String> {
        let journal = std::env::var_os("KOLIMI_AUDIT_ANCHOR_LOG")
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty());
        let url = std::env::var("KOLIMI_AUDIT_ANCHOR_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let token = std::env::var("KOLIMI_AUDIT_ANCHOR_TOKEN")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if url.is_none() && token.is_some() {
            return Err("KOLIMI_AUDIT_ANCHOR_TOKEN requires KOLIMI_AUDIT_ANCHOR_URL".into());
        }
        if let Some(url) = &url {
            validate_url(url)?;
        }
        if journal.is_none() && url.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            journal,
            url,
            token,
        }))
    }

    /// Whether the journal sink is configured.
    pub fn journal_enabled(&self) -> bool {
        self.journal.is_some()
    }

    /// Whether the HTTP sink is configured.
    pub fn http_enabled(&self) -> bool {
        self.url.is_some()
    }

    /// Whether any sink is configured.
    pub fn enabled(&self) -> bool {
        self.journal_enabled() || self.http_enabled()
    }
}

fn validate_url(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(format!(
            "KOLIMI_AUDIT_ANCHOR_URL must use https (plain http is allowed only for loopback): {url}"
        ));
    };
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.contains('@') {
        return Err("KOLIMI_AUDIT_ANCHOR_URL must not contain userinfo".into());
    }
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        Ok(())
    } else {
        Err(format!(
            "KOLIMI_AUDIT_ANCHOR_URL must use https (plain http is allowed only for loopback): {url}"
        ))
    }
}

/// Errors while draining anchors.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// Database failure.
    #[error("database: {0}")]
    Db(#[from] kolimi_db::DbError),
    /// HTTP client setup failure.
    #[error("anchor http: {0}")]
    Http(#[from] reqwest::Error),
    /// Journal failure.
    #[error("anchor journal: {0}")]
    Journal(#[from] std::io::Error),
}

/// What one drain pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainReport {
    /// Records appended to the journal.
    pub journaled: u64,
    /// Records delivered to the HTTP sink.
    pub delivered: u64,
    /// Rows with at least one failed sink.
    pub failed: u64,
}

/// Delivers due outbox rows to the configured sinks.
pub async fn drain(
    db: &Db,
    config: &AnchorConfig,
    metrics: Option<&Metrics>,
    limit: i64,
) -> Result<DrainReport, AnchorError> {
    let mut report = DrainReport::default();
    if !config.enabled() {
        return Ok(report);
    }
    let now = now_millis();
    let rows = db
        .audit_anchor_pending(
            config.journal_enabled(),
            config.http_enabled(),
            now,
            limit.clamp(1, 1000),
        )
        .await?;
    let client = if config.http_enabled() {
        Some(
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(10))
                .build()?,
        )
    } else {
        None
    };

    for row in rows {
        let mut row_failed = false;
        if let Some(path) = &config.journal
            && row.journaled_at.is_none()
        {
            match append_journal(path, row.payload.trim_end()) {
                Ok(()) => {
                    db.audit_anchor_mark_journaled(row.checkpoint_id, now)
                        .await?;
                    report.journaled += 1;
                    if let Some(metrics) = metrics {
                        metrics.audit_anchor_delivered("journal", 1);
                    }
                }
                Err(error) => {
                    row_failed = true;
                    record_failure(
                        db,
                        &row,
                        "journal",
                        &format!("journal: {error}"),
                        now,
                        metrics,
                    )
                    .await?;
                }
            }
        }
        if let (Some(client), Some(url)) = (client.as_ref(), config.url.as_ref())
            && row.delivered_at.is_none()
        {
            match deliver_http(client, url, config.token.as_deref(), &row.payload).await {
                Ok(()) => {
                    db.audit_anchor_mark_delivered(row.checkpoint_id, now)
                        .await?;
                    report.delivered += 1;
                    if let Some(metrics) = metrics {
                        metrics.audit_anchor_delivered("http", 1);
                    }
                }
                Err(Failure::Retry(error)) => {
                    row_failed = true;
                    record_failure(db, &row, "http", &format!("http: {error}"), now, metrics)
                        .await?;
                }
                Err(Failure::Permanent(error)) => {
                    row_failed = true;
                    db.audit_anchor_mark_failed(
                        row.checkpoint_id,
                        &format!("http: {error}"),
                        i64::MAX,
                    )
                    .await?;
                    if let Some(metrics) = metrics {
                        metrics.audit_anchor_failure("http");
                    }
                }
            }
        }
        if row_failed {
            report.failed += 1;
        }
    }
    if let Some(metrics) = metrics {
        let pending = db
            .audit_anchor_pending_count(config.journal_enabled(), config.http_enabled())
            .await?;
        metrics.set_audit_anchor_pending(pending);
    }
    Ok(report)
}

async fn record_failure(
    db: &Db,
    row: &AuditAnchorOutboxRow,
    sink: &str,
    error: &str,
    now: i64,
    metrics: Option<&Metrics>,
) -> Result<(), AnchorError> {
    let next = now + backoff_millis(row.attempts.saturating_add(1));
    db.audit_anchor_mark_failed(row.checkpoint_id, error, next)
        .await?;
    if let Some(metrics) = metrics {
        metrics.audit_anchor_failure(sink);
    }
    Ok(())
}

fn backoff_millis(attempts: i64) -> i64 {
    let exponent = attempts.clamp(1, 12) as u32;
    let base = 30_000i64.saturating_mul(1i64 << exponent.min(20));
    base.min(24 * 60 * 60 * 1000)
}

/// Appends one anchor record and fsyncs it.
fn append_journal(path: &Path, payload: &str) -> Result<(), std::io::Error> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let existed = path.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    use std::io::Write;
    file.write_all(payload.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    #[cfg(unix)]
    if !existed
        && let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// One HTTP delivery failure.
enum Failure {
    /// Retryable (network, timeout, 408/429/5xx).
    Retry(String),
    /// Permanent (other 4xx).
    Permanent(String),
}

async fn deliver_http(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    payload: &str,
) -> Result<(), Failure> {
    let idempotency = serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        .and_then(|value| {
            value
                .get("checkpoint_hash")
                .and_then(|hash| hash.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let mut request = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(payload.to_string());
    if !idempotency.is_empty() {
        request = request.header("Idempotency-Key", idempotency);
    }
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .map_err(|error| Failure::Retry(error.to_string()))?;
    let status = response.status().as_u16();
    match status {
        200..=299 | 409 => Ok(()),
        408 | 429 | 500..=599 => Err(Failure::Retry(format!("status {status}"))),
        _ => Err(Failure::Permanent(format!("status {status}"))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{backoff_millis, validate_url};

    #[test]
    fn anchor_urls_require_tls_except_loopback() {
        assert!(validate_url("https://anchors.example.net/kolimi").is_ok());
        assert!(validate_url("http://127.0.0.1:9000/anchor").is_ok());
        assert!(validate_url("http://localhost:9000/anchor").is_ok());
        assert!(validate_url("http://[::1]:9000/anchor").is_ok());
        assert!(validate_url("http://anchors.example.net/kolimi").is_err());
        assert!(validate_url("http://localhost.evil.example/x").is_err());
        assert!(validate_url("http://user@localhost/x").is_err());
        assert!(validate_url("ftp://localhost/x").is_err());
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_millis(0), 60_000);
        assert!(backoff_millis(3) > backoff_millis(1));
        assert_eq!(backoff_millis(100), 24 * 60 * 60 * 1000);
    }
}
