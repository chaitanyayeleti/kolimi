# Metrics reference

`/metrics` exposes a small, bounded Prometheus registry. This page lists the
metric families and gives useful queries and alert starting points. Client
setup, authentication, and the HTML dashboard are covered in
[operations.md](operations.md#metrics).

A ready-to-import Grafana dashboard is in
[`grafana/kolimi.json`](grafana/kolimi.json). In Grafana, choose
**Dashboards → New → Import**, upload the file, and select your Prometheus
datasource.

On Kubernetes, set `metrics.token` or preferably
`metrics.existingSecret`/`metrics.secretKey` in the Helm values; the chart
passes it to the server as `KOLIMI_METRICS_TOKEN`.

## Enable the metrics token

`KOLIMI_METRICS_TOKEN` is supported by **0.5.1 and later** and is read at
server startup. Generate a token once:

```sh
openssl rand -hex 32
```

Do not reuse an admin password or commit the token to the repository.

### systemd

Add the token to the file referenced by the unit (the packaged unit uses
`/etc/kolimi/kolimi.env`):

```sh
sudoedit /etc/kolimi/kolimi.env
```

```sh
KOLIMI_METRICS_TOKEN=paste-the-token-here
```

Then restart the service:

```sh
sudo systemctl restart kolimi
```

Check the unit name first if it is not `kolimi`:

```sh
systemctl list-units --type=service | rg kolimi
```

### Docker Compose

Put the token in the `.env` file next to your Compose file:

```sh
KOLIMI_METRICS_TOKEN=paste-the-token-here
```

The packaged Compose files pass it through. If you use a custom Compose
file, add the environment entry yourself:

```yaml
services:
  kolimi:
    environment:
      KOLIMI_METRICS_TOKEN: ${KOLIMI_METRICS_TOKEN}
```

Recreate the container:

```sh
docker compose up -d kolimi
```

### Docker run

Environment variables cannot be added to a running container. Recreate it
with the token:

```sh
docker run ... \
  -e KOLIMI_METRICS_TOKEN=paste-the-token-here \
  ghcr.io/chaitanyayeleti/kolimi:0.7.1
```

### Kubernetes / Helm

Prefer a Secret:

```sh
kubectl create secret generic kolimi-metrics \
  --from-literal=metrics-token="$(openssl rand -hex 32)"
```

```yaml
metrics:
  existingSecret: kolimi-metrics
  secretKey: metrics-token
```

For a quick test, `metrics.token: "…"` also works but keeps the token in
the values file.

### Run the binary directly

```sh
KOLIMI_METRICS_TOKEN=paste-the-token-here \
KOLIMI_DATA=/var/lib/kolimi \
kolimi-server serve
```

### Verify

```sh
TOKEN=paste-the-token-here

curl -fsS -H "Authorization: Bearer $TOKEN" \
  https://cloud.example.com/metrics | head
```

The token is accepted on `/metrics` only; it does not create a session or
grant access to the admin API. The same value also works as
`X-Kolimi-Metrics-Token`.

## Metric catalog

### HTTP

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kolimi_http_requests_total` | counter | `method`, `path`, `status` | Requests by route template and status |
| `kolimi_http_request_duration_seconds` | histogram | `method`, `path` | Handler latency |
| `kolimi_http_request_body_bytes_total` | counter | `method`, `path` | Declared request-body bytes |
| `kolimi_http_response_body_bytes_total` | counter | `method`, `path` | Declared response-body bytes |
| `kolimi_http_requests_in_flight` | gauge | — | Requests currently being handled |

`path` is an axum route template such as `/api/users/{username}`, never the
raw request path. Unknown methods collapse to `method="other"`; unmatched
paths collapse to `path="unmatched"`.

### Files and transfer

| Metric | Type | Meaning |
| --- | --- | --- |
| `kolimi_file_uploads_total` | counter | Manifest commits that created a file version |
| `kolimi_file_upload_bytes_total` | counter | Logical bytes committed by clients |
| `kolimi_file_download_bytes_total` | counter | Logical bytes sent through API/public downloads |
| `kolimi_chunk_upload_bytes_total` | counter | Chunk bytes received |
| `kolimi_chunk_download_bytes_total` | counter | Chunk bytes sent |
| `kolimi_files` | gauge | Live files outside trash |
| `kolimi_trash_nodes` | gauge | Nodes currently in trash |
| `kolimi_file_versions` | gauge | Stored file versions |
| `kolimi_browse_page_entries` | histogram | Entries returned per `/api/browse` response |
| `kolimi_browse_pages_total` | counter | Directory pages by `has_more` (`true` / `false`) |

### Previews and auth

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kolimi_preview_runs_total` | counter | `outcome` | Preview outcomes (`ok`, `error`, `unsupported`) |
| `kolimi_preview_duration_seconds` | histogram | `outcome` | Preview worker duration |
| `kolimi_login_failures_total` | counter | — | Rejected password/passkey/TOTP attempts |
| `kolimi_logins_total` | counter | `outcome` | Login outcomes (`password`, `totp`, `recovery`, `passkey`, `totp_required`, `failure`) |
| `kolimi_auth_timestamp_writes_total` | counter | `credential`, `result` | Session/app-password timestamp refreshes: `written`, `skipped`, `error` |
| `kolimi_sessions_active` | gauge | — | Live, unexpired sessions |
| `kolimi_app_passwords_active` | gauge | — | Stored per-device app passwords |

### Users, storage, and quotas

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kolimi_users_total` | gauge | `state` | Accounts by `enabled` / `disabled` |
| `kolimi_users_mfa_pending` | gauge | — | Accounts still requiring MFA setup |
| `kolimi_users_by_usage_bucket` | gauge | `bucket` | Accounts by quota usage |
| `kolimi_storage_used_bytes` | gauge | — | Sum of cached per-account usage |
| `kolimi_user_used_bytes` | gauge | `user` | Per-account usage (opt-in) |

Usage buckets are `0`, `1-50`, `50-90`, `90-100`, `over`, and `unlimited`.
Set `KOLIMI_METRICS_PER_USER=1` to expose per-user gauges. Those labels
contain usernames and scale with the account count, so leave them off unless
you need them.

The user/quota gauges and the session/app-password/MLS/file/version gauges
are rebuilt at most every 30 seconds, not on every scrape.

### MLS and SSE

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kolimi_mls_devices` | gauge | — | MLS device-roster entries |
| `kolimi_mls_key_packages` | gauge | — | Live, unconsumed key packages |
| `kolimi_mls_commits_total` | counter | `result` | `ok`, `conflict`, `error` |
| `kolimi_sse_connections_active` | gauge | — | Open sync event streams |
| `kolimi_sse_connections_rejected_total` | counter | — | Streams refused at the 64-stream cap |
| `kolimi_rate_limited_total` | counter | `surface` | `auth`, `totp`, `invite`, `recovery`, `link`, `preview`, `mls` |

### Database, janitor, and process

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kolimi_db_pool_connections` | gauge | `state` | SQLite pool `in_use` / `idle` |
| `kolimi_db_errors_total` | counter | — | Cumulative SQLite query errors |
| `kolimi_db_busy_errors_total` | counter | — | Cumulative `SQLITE_BUSY` / `SQLITE_LOCKED` errors |
| `kolimi_db_write_transactions_total` | counter | — | Cumulative SQLite write transactions begun |
| `kolimi_audit_entries_appended_total` | counter | — | Cumulative audit rows appended |
| `kolimi_change_events_appended_total` | counter | — | Cumulative change-feed rows appended |
| `kolimi_indexer_runs_total` | counter | `result` | Search-indexer passes (`success` / `error`) |
| `kolimi_indexer_duration_seconds` | histogram | `result` | Search-indexer pass duration |
| `kolimi_indexer_documents_total` | counter | `outcome` | Documents `indexed` / `removed` |
| `kolimi_janitor_runs_total` | counter | `result` | `success` / `error` |
| `kolimi_janitor_duration_seconds` | histogram | `result` | Pass duration |
| `kolimi_janitor_events_total` | counter | `kind` | Objects processed |
| `kolimi_janitor_last_success_timestamp_seconds` | gauge | — | Last successful pass |
| `kolimi_audit_checkpoints_signed_total` | counter | — | Checkpoints sealed with a signature |
| `kolimi_audit_signing_errors_total` | counter | — | Sealing failures caused by signing |
| `kolimi_audit_anchor_pending` | gauge | — | Anchors waiting for a configured sink |
| `kolimi_audit_anchor_delivered_total` | counter | `sink` | `journal` / `http` |
| `kolimi_audit_anchor_failures_total` | counter | `sink` | `journal` / `http` |
| `kolimi_process_resident_memory_bytes` | gauge | — | RSS (Linux) |
| `kolimi_process_threads` | gauge | — | Thread count (Linux) |
| `kolimi_process_open_fds` | gauge | — | Open file descriptors (Linux) |
| `kolimi_process_cpu_seconds_total` | counter | — | Cumulative process CPU time (Linux) |
| `kolimi_build_info` | gauge | `version` | Build version (value `1`) |
| `kolimi_start_time_seconds` | gauge | — | Process start time |

Janitor event kinds include `retention_users`, `trash_purged`,
`versions_pruned`, `gc_users`, `chunks_deleted`, `manifests_deleted`,
`manifests_migrated`, `scrub_users`, `link_sessions_expired`,
`enrollments_expired`, `mls_key_packages_pruned`, `mls_devices_pruned`,
`mls_messages_pruned`, `mls_keyrings_pruned`, `scrub_checked`,
`scrub_corrupt`, `reconciled`, `audit_checkpoints_sealed`,
`audit_checkpoints_signed`, `audit_anchors_journaled`, and
`audit_anchors_delivered`.

The janitor and indexer now schedule bounded per-account batches: accounts
with expired trash/versions or an uncollected delete go first, then the
least-recently-swept and least-recently-scrubbed accounts. `gc_users` and
`scrub_users` show how many accounts each pass touched.

## Useful PromQL

**5xx ratio**

```promql
sum(rate(kolimi_http_requests_total{status=~"5.."}[5m]))
/
sum(rate(kolimi_http_requests_total[5m]))
```

**p95 latency by route**

```promql
histogram_quantile(
  0.95,
  sum by (le, path) (
    rate(kolimi_http_request_duration_seconds_bucket[5m])
  )
)
```

**Upload and download throughput**

```promql
sum(rate(kolimi_file_upload_bytes_total[5m]))
sum(rate(kolimi_file_download_bytes_total[5m]))
sum(rate(kolimi_chunk_upload_bytes_total[5m]))
```

**Login failures and rate limiting**

```promql
sum(rate(kolimi_login_failures_total[5m]))
sum by (surface) (rate(kolimi_rate_limited_total[5m]))
```

**Storage and accounts near quota**

```promql
kolimi_storage_used_bytes
sum(kolimi_users_by_usage_bucket{bucket=~"90-100|over"})
kolimi_users_mfa_pending
```

**Sync event-stream pressure**

```promql
kolimi_sse_connections_active
sum(rate(kolimi_sse_connections_rejected_total[5m]))
```

**Janitor health**

```promql
time() - kolimi_janitor_last_success_timestamp_seconds
sum by (result) (rate(kolimi_janitor_runs_total[1h]))
increase(kolimi_janitor_events_total{kind="scrub_corrupt"}[1h])
```

**Database pool**

```promql
kolimi_db_pool_connections{state="in_use"}
sum(rate(kolimi_db_errors_total[5m]))
sum(rate(kolimi_db_busy_errors_total[5m]))
```

**Write and audit pressure**

```promql
sum(rate(kolimi_db_write_transactions_total[5m]))
sum(rate(kolimi_change_events_appended_total[5m]))
sum(rate(kolimi_audit_entries_appended_total[5m]))
histogram_quantile(0.95, sum(rate(kolimi_browse_page_entries_bucket[5m])) by (le))
```

**Auth timestamp throttle**

```promql
sum by (result) (rate(kolimi_auth_timestamp_writes_total[5m]))
```

The `skipped` share should dominate once clients poll repeatedly inside the
one-minute window; a rising `written` share means the refresh is happening
more often than intended.

**Version**

```promql
kolimi_build_info
```

## Alert starting points

| Alert | Expression |
| --- | --- |
| Metrics target down | `up{job="kolimi"} == 0` |
| High 5xx ratio | 5xx ratio above `0.01` for 10m |
| Sustained rate limiting | `sum(rate(kolimi_rate_limited_total[5m])) > 1` for 10m |
| Janitor stale | `time() - kolimi_janitor_last_success_timestamp_seconds > 7200` |
| Corrupt blob found | `increase(kolimi_janitor_events_total{kind="scrub_corrupt"}[1h]) > 0` |
| Accounts near quota | `sum(kolimi_users_by_usage_bucket{bucket=~"90-100|over"}) > 0` |
| SSE rejections | `sum(rate(kolimi_sse_connections_rejected_total[5m])) > 0` |
| Preview failure spike | `sum(rate(kolimi_preview_runs_total{outcome="error"}[5m])) > 0.1` |
| DB pool saturation | `kolimi_db_pool_connections{state="in_use"} >= 8` |
| SQLite contention | `sum(rate(kolimi_db_busy_errors_total[5m])) > 0` for 10m |

Tune thresholds for your traffic. The built-in HTML dashboard is for a quick
look; use Prometheus and Grafana for history and alerting.
