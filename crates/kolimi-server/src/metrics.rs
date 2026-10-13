//! Prometheus metrics.
//!
//! Deliberately small and content-free: request counts and latencies by
//! route template, plus a handful of application counters. No file
//! names, paths, or user identifiers are ever labeled.

use std::time::Instant;

use axum::{
    extract::{Extension, MatchedPath, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use serde::Deserialize;

use kolimi_auth::CurrentUser;
use kolimi_db::User;

use crate::AppState;

/// Registry and counters for one server process.
#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    requests: IntCounterVec,
    duration: HistogramVec,
    uploads: IntCounter,
    previews: IntCounterVec,
    login_failures: IntCounter,
    usage_bucket: IntGaugeVec,
    user_used: IntGaugeVec,
    per_user_usage: bool,
}

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
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
            &["method", "path"],
        )?;
        let uploads = IntCounter::new(
            "kolimi_file_uploads_total",
            "Client manifest commits that created a new file version",
        )?;
        let previews = IntCounterVec::new(
            Opts::new("kolimi_preview_runs_total", "Preview worker outcomes"),
            &["outcome"],
        )?;
        let login_failures = IntCounter::new(
            "kolimi_login_failures_total",
            "Rejected password or second-factor attempts",
        )?;
        let usage_bucket = IntGaugeVec::new(
            Opts::new(
                "kolimi_users_by_usage_bucket",
                "Accounts by how full their quota is (low cardinality)",
            ),
            &["bucket"],
        )?;
        let user_used = IntGaugeVec::new(
            Opts::new(
                "kolimi_user_used_bytes",
                "Per-user used storage bytes (opt-in: KOLIMI_METRICS_PER_USER=1)",
            ),
            &["user"],
        )?;
        registry.register(Box::new(requests.clone()))?;
        registry.register(Box::new(duration.clone()))?;
        registry.register(Box::new(uploads.clone()))?;
        registry.register(Box::new(previews.clone()))?;
        registry.register(Box::new(login_failures.clone()))?;
        registry.register(Box::new(usage_bucket.clone()))?;
        registry.register(Box::new(user_used.clone()))?;
        Ok(Self {
            registry,
            requests,
            duration,
            uploads,
            previews,
            login_failures,
            usage_bucket,
            user_used,
            per_user_usage: std::env::var("KOLIMI_METRICS_PER_USER")
                .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes")),
        })
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
            if self.per_user_usage {
                self.user_used
                    .with_label_values(&[&account.username])
                    .set(used as i64);
            }
        }
        for (bucket, count) in counts {
            self.usage_bucket.with_label_values(&[bucket]).set(count);
        }
    }

    fn observe(&self, method: &str, path: &str, status: u16, seconds: f64) {
        self.requests
            .with_label_values(&[method, path, &status.to_string()])
            .inc();
        self.duration
            .with_label_values(&[method, path])
            .observe(seconds);
    }

    /// Counts a committed upload.
    pub fn upload(&self) {
        self.uploads.inc();
    }

    /// Counts a preview worker outcome (`ok`, `error`, `unsupported`).
    pub fn preview(&self, outcome: &str) {
        self.previews.with_label_values(&[outcome]).inc();
    }

    /// Counts a rejected login (bad password, TOTP, or recovery code).
    pub fn login_failure(&self) {
        self.login_failures.inc();
    }

    /// Renders the Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        if encoder
            .encode(&self.registry.gather(), &mut buffer)
            .is_err()
        {
            return String::new();
        }
        String::from_utf8(buffer).unwrap_or_default()
    }

    /// Renders the same registry as a small self-contained HTML dashboard
    /// for humans browsing `/metrics`. Scrapers still get the text format
    /// via content negotiation in `handler`.
    ///
    /// Parses the text exposition rather than the protobuf registry so it
    /// stays stable across `prometheus`/`protobuf` API changes.
    pub fn render_html(&self) -> String {
        let mut out = String::new();
        let mut section: Option<(String, String, String, String)> = None;
        for line in self.render().lines() {
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
        format!("{HTML_HEAD}{out}{HTML_TAIL}")
    }
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
pub async fn record(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    let started = Instant::now();
    let response = next.run(request).await;
    state.metrics.observe(
        &method,
        &path,
        response.status().as_u16(),
        started.elapsed().as_secs_f64(),
    );
    response
}

/// Query for `GET /metrics`.
#[derive(Deserialize)]
pub struct MetricsQuery {
    /// `?format=text` forces the Prometheus text format in a browser.
    #[serde(default)]
    format: Option<String>,
}

/// `GET /metrics` — administrators only.
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
    if let Ok(users) = state.db.list_users().await {
        state
            .metrics
            .refresh_user_usage(&users, state.vfs.store().default_quota());
    }
    let wants_html = query.format.as_deref() != Some("text")
        && headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/html"));
    if wants_html {
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            state.metrics.render_html(),
        )
            .into_response()
    } else {
        (
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            state.metrics.render(),
        )
            .into_response()
    }
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
            quota_bytes: quota,
            used_bytes: used,
            usage_updated_at: None,
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
    }
}
