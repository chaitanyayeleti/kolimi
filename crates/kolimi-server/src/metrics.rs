//! Prometheus metrics.
//!
//! Deliberately small and content-free: request counts and latencies by
//! route template, plus a handful of application counters. No file
//! names, paths, or user identifiers are ever labeled.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Extension, MatchedPath, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
};

use kolimi_auth::CurrentUser;

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
        registry.register(Box::new(requests.clone()))?;
        registry.register(Box::new(duration.clone()))?;
        registry.register(Box::new(uploads.clone()))?;
        registry.register(Box::new(previews.clone()))?;
        registry.register(Box::new(login_failures.clone()))?;
        Ok(Self {
            registry,
            requests,
            duration,
            uploads,
            previews,
            login_failures,
        })
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
}

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

/// `GET /metrics` — Prometheus scrape endpoint, administrators only.
///
/// Authenticate with an admin session (browser) or HTTP Basic with an
/// admin's credentials (a scraper).
pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state.metrics.render(),
    )
        .into_response()
}

/// Shared metrics handle for subsystems that count without an AppState.
pub type SharedMetrics = Arc<Metrics>;
