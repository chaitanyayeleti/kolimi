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

### Previews and auth

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kolimi_preview_runs_total` | counter | `outcome` | Preview outcomes (`ok`, `error`, `unsupported`) |
| `kolimi_preview_duration_seconds` | histogram | `outcome` | Preview worker duration |
| `kolimi_login_failures_total` | counter | — | Rejected password/passkey/TOTP attempts |
| `kolimi_logins_total` | counter | `outcome` | Login outcomes (`password`, `totp`, `recovery`, `passkey`, `totp_required`, `failure`) |
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
| `kolimi_janitor_runs_total` | counter | `result` | `success` / `error` |
| `kolimi_janitor_duration_seconds` | histogram | `result` | Pass duration |
| `kolimi_janitor_events_total` | counter | `kind` | Objects processed |
| `kolimi_janitor_last_success_timestamp_seconds` | gauge | — | Last successful pass |
| `kolimi_process_resident_memory_bytes` | gauge | — | RSS (Linux) |
| `kolimi_process_threads` | gauge | — | Thread count (Linux) |
| `kolimi_process_open_fds` | gauge | — | Open file descriptors (Linux) |
| `kolimi_process_cpu_seconds_total` | counter | — | Cumulative process CPU time (Linux) |
| `kolimi_build_info` | gauge | `version` | Build version (value `1`) |
| `kolimi_start_time_seconds` | gauge | — | Process start time |

Janitor event kinds include `trash_purged`, `versions_pruned`,
`chunks_deleted`, `manifests_deleted`, `link_sessions_expired`,
`enrollments_expired`, `mls_key_packages_pruned`, `mls_devices_pruned`,
`mls_messages_pruned`, `mls_keyrings_pruned`, `scrub_checked`,
`scrub_corrupt`, and `reconciled`.

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
