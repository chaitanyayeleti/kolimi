//! Audit anchor delivery (RFC 0014).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use kolimi_db::{AuditSigner, Db};
use kolimi_server::anchor::{AnchorConfig, drain};
use serde_json::json;

type Requests = Arc<Mutex<Vec<(Option<String>, Option<String>)>>>;

#[derive(Clone, Default)]
struct Sink {
    requests: Requests,
    fail: Arc<AtomicBool>,
}

async fn receive(State(sink): State<Sink>, headers: HeaderMap, body: String) -> StatusCode {
    let idempotency = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    assert!(body.contains("kolimi-audit-anchor-v1"));
    sink.requests
        .lock()
        .unwrap()
        .push((idempotency, authorization));
    if sink.fail.load(Ordering::SeqCst) {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    }
}

async fn signed_checkpoint(dir: &Path) -> (Db, AuditSigner) {
    let db = Db::connect(&dir.join("test.db")).await.unwrap();
    for name in ["a", "b"] {
        db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
            .await
            .unwrap();
    }
    let signer = AuditSigner::generate(&dir.join("audit.key"), None).unwrap();
    db.audit_seal_with(10, Some(&signer), true)
        .await
        .unwrap()
        .unwrap();
    (db, signer)
}

async fn start_sink() -> (Sink, String) {
    let sink = Sink::default();
    let app = Router::new()
        .route("/anchor", post(receive))
        .with_state(sink.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (sink, format!("http://{address}/anchor"))
}

#[tokio::test]
async fn http_sink_delivers_once_with_idempotency_and_auth() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _signer) = signed_checkpoint(dir.path()).await;
    let record = db.audit_anchor_record(None).await.unwrap().unwrap();
    let (sink, url) = start_sink().await;
    let config = AnchorConfig {
        journal: None,
        url: Some(url),
        token: Some("secret".into()),
    };

    let report = drain(&db, &config, None, 10).await.unwrap();
    assert_eq!(report.delivered, 1, "{report:?}");
    assert_eq!(report.failed, 0, "{report:?}");
    {
        let requests = sink.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].0.as_deref(),
            Some(record.checkpoint_hash.as_str())
        );
        assert_eq!(requests[0].1.as_deref(), Some("Bearer secret"));
    }

    // Already delivered: nothing is pending, so no second request.
    let report = drain(&db, &config, None, 10).await.unwrap();
    assert_eq!(report.delivered, 0, "{report:?}");
    assert_eq!(sink.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn http_failures_back_off_and_retry() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _signer) = signed_checkpoint(dir.path()).await;
    let (sink, url) = start_sink().await;
    let config = AnchorConfig {
        journal: None,
        url: Some(url),
        token: None,
    };
    sink.fail.store(true, Ordering::SeqCst);

    let report = drain(&db, &config, None, 10).await.unwrap();
    assert_eq!(report.failed, 1, "{report:?}");
    let row = &db.audit_anchor_outbox(10).await.unwrap()[0];
    assert_eq!(row.attempts, 1);
    assert!(row.next_attempt_at > kolimi_db::now_millis());
    assert!(
        row.last_error
            .as_deref()
            .unwrap_or_default()
            .contains("500")
    );

    // The backoff defers the next attempt.
    let report = drain(&db, &config, None, 10).await.unwrap();
    assert_eq!(report.failed, 0, "{report:?}");
    assert_eq!(sink.requests.lock().unwrap().len(), 1);

    sqlx::query("UPDATE audit_anchor_outbox SET next_attempt_at = 0")
        .execute(db.pool())
        .await
        .unwrap();
    sink.fail.store(false, Ordering::SeqCst);
    let report = drain(&db, &config, None, 10).await.unwrap();
    assert_eq!(report.delivered, 1, "{report:?}");
    assert_eq!(sink.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn journal_sink_appends_once_and_survives_a_retry() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _signer) = signed_checkpoint(dir.path()).await;
    let journal = dir.path().join("anchors").join("checkpoints.jsonl");
    let config = AnchorConfig {
        journal: Some(journal.clone()),
        url: None,
        token: None,
    };

    let report = drain(&db, &config, None, 10).await.unwrap();
    assert_eq!(report.journaled, 1, "{report:?}");
    let first = std::fs::read_to_string(&journal).unwrap();
    assert_eq!(first.lines().count(), 1);
    assert!(first.contains("kolimi-audit-anchor-v1"));

    let report = drain(&db, &config, None, 10).await.unwrap();
    assert_eq!(report.journaled, 0, "{report:?}");
    assert_eq!(
        std::fs::read_to_string(&journal).unwrap().lines().count(),
        1,
        "journaled_at prevents duplicate appends"
    );
}
