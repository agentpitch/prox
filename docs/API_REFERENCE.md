# HTTP API reference

Base address: configured `http.listen`, default `127.0.0.1:18080`.

The API is intended for localhost use only.

## `GET /api/health`

Response:

```json
{"ok": true, "version": "v0.43-rc.6", "pid": 1234}
```

`version` is injected at build time. Unversioned developer builds report
`"dev"`. `pid` identifies the exact running process. During a verified updater
handoff, the newly started current-format build also returns a short-lived
`update_token`; it is omitted during normal operation and from legacy builds.

## `GET /api/config`

Returns the full current config.

## `PUT /api/config`

Replaces the full config.

Behavior:

- config is normalized;
- config is validated;
- a non-zero `updated_at` from the submitted document is used as an optimistic concurrency token;
- stale updates return HTTP `409 Conflict` instead of overwriting a newer config;
- a zero or omitted token remains an unconditional update for legacy API clients;
- `updated_at` is rewritten server-side;
- the JSON file is written atomically.
- config replacement returns HTTP `409 Conflict` while an application update is
  running, so the helper restarts the exact listener/service identity captured
  for that transaction.

Transparent-listener and routing changes are applied by a transactional runtime restart; if activation fails, the previous runtime/configuration is restored. Changing the HTTP listen address still requires a service/process restart.

## `GET /api/snapshot`

Returns the WebUI snapshot.

Optional query parameters:

- `include_logs=0` - omit historical log payloads for lighter periodic refreshes.

Fields:

- `connections`
- `new_connections`
- `logs`
- `traffic`
- `traffic_totals`
- `traffic_bucket_seconds`
- `rule_stats`
- `retention_minutes`
- `new_baseline_minutes`
- `new_recent_minutes`

Notes:

- `traffic` is a bounded bucketed series for the full retention window rather than a raw per-second dump.
- `traffic_bucket_seconds` tells the WebUI how many seconds each traffic bucket represents.
- `new_connections` contains application/address/port signatures first seen during `new_recent_minutes`; the comparison baseline is the currently configured retained history window reported as `new_baseline_minutes`. If the retained window is not longer than the recent window, the result is empty.

This is heavier than tray data and is intended for the WebUI, not for the tray.

## `GET /api/rules/activity`

Returns bounded activity timelines for the requested stable rule IDs. This is
used for the visible Rules-page sparklines and does not create an in-memory
history cache.

Query parameters:

- repeated `id=<rule-id>` values; at most 50 unique non-empty IDs;
- `points`, default 40, range 2–60;
- `window_minutes`, default 15, range 1–60 and clamped to configured retention.

Example:

```text
/api/rules/activity?id=default&id=browser&points=40&window_minutes=15
```

Response shape:

```json
{
  "generated_at": "2026-08-03T12:00:00Z",
  "window_minutes": 15,
  "bucket_seconds": 22.5,
  "points": 40,
  "series": [
    {
      "rule_id": "browser",
      "rule_name": "Browser",
      "action": "proxy",
      "connections": 12,
      "up_bytes": 1024,
      "down_bytes": 4096,
      "buckets": [
        {"time": "2026-08-03T11:45:00Z", "connections": 1, "up_bytes": 64, "down_bytes": 128}
      ]
    }
  ]
}
```

Rule activity totals are aggregated for up to 15 seconds and stored with the
latest real event time in that aggregate. The endpoint performs a bounded
reverse scan of retained history. When the lower window boundary cuts through
one stored aggregate, the result may include an older portion of that boundary
aggregate; values are not proportionally split. IDs are opaque and matched
exactly after outer whitespace is trimmed.
Direct-connection byte counts may be unavailable because direct traffic does
not necessarily traverse the relay.

## `GET /api/rules/condition-activity`

Returns a bounded, lazy detail view for one exact stable rule ID. It shows
which authored `Applications + Target hosts + Ports` alternatives actually
matched observed TCP connections. It does not expand the rule into a Cartesian
product and does not keep a permanent in-memory telemetry cache.

Query parameters:

- exactly one `id=<rule-id>`; the opaque ID is matched case-sensitively after
  trimming only its outer whitespace;
- `window_minutes`, default 15, range 1–60 and clamped to configured retention;
- `limit`, default 20, range 1–100, limiting returned condition tuples.

Example response (abbreviated):

```json
{
  "generated_at": "2026-08-04T12:00:00Z",
  "rule_id": "browser",
  "window_minutes": 15,
  "total_hits": 10,
  "other_hits": 0,
  "unattributed_hits": 0,
  "truncated": false,
  "source_hits": {"intercepted": 9, "direct_observer": 1},
  "conditions": [
    {
      "application": "chrome.exe",
      "host": "*.example.com",
      "port": "443",
      "hits": 10,
      "share": 1,
      "last_seen": "2026-08-04T11:59:48Z",
      "sources": {"intercepted": 9, "direct_observer": 1}
    }
  ],
  "dimensions": {
    "applications": {
      "total_hits": 10,
      "other_hits": 0,
      "truncated": false,
      "values": [
        {
          "value": "chrome.exe",
          "hits": 10,
          "share": 1,
          "last_seen": "2026-08-04T11:59:48Z",
          "sources": {"intercepted": 9, "direct_observer": 1}
        }
      ]
    },
    "hosts": {"total_hits": 10, "other_hits": 0, "truncated": false, "values": [{"value": "*.example.com", "hits": 10, "share": 1, "last_seen": "2026-08-04T11:59:48Z", "sources": {"intercepted": 9, "direct_observer": 1}}]},
    "ports": {"total_hits": 10, "other_hits": 0, "truncated": false, "values": [{"value": "443", "hits": 10, "share": 1, "last_seen": "2026-08-04T11:59:48Z", "sources": {"intercepted": 9, "direct_observer": 1}}]}
  },
  "accuracy": {
    "unit": "tcp_connection",
    "attribution": "first_matching_alternative",
    "intercepted_complete": true,
    "direct_complete": false,
    "boundary_seconds": 15,
    "notice": "..."
  }
}
```

Semantics and limits:

- one `hit` is one newly observed TCP connection, not one HTTP request;
- if alternatives overlap, the first matching alternative in that dimension
  receives the hit. Case-insensitive application/host labels are canonicalized
  to lowercase (application `/` becomes `\\`); quotes and outer whitespace are
  removed. Unrestricted applications keep `*` versus `Any`, while an empty
  unrestricted field is reported as `Any`;
- `share` always uses `total_hits` as its denominator; `other_hits` is the
  observed count omitted from the returned top tuples. `unattributed_hits` is
  the subset whose detailed label was deliberately collapsed under overload;
- collection admits at most 256 distinct detailed keys per 15-second write
  bucket inside the existing 1,024-detail/4,096-rule pending bounds. Repeated
  hits for an admitted tuple stay aggregated in memory until that bucket
  closes, so WebUI snapshots cannot multiply JSONL records. Further hits and
  labels that are invalid UTF-8 or exceed 512 bytes are folded into a
  source-aware overflow aggregate, preserving the ordinary rule connection
  total while marking detail as truncated;
- the tuple query also keeps at most 1,024 transient groups and returns at most
  `limit`; each marginal dimension keeps at most 512 transient values;
- marginal `dimensions` are calculated independently of tuple top-N. The UI
  can merge them with the current raw rule tokens without constructing a
  potentially enormous Cartesian product;
- when a dimension has `truncated=false`, an authored token absent from
  `values` has zero *observed* hits in the requested window. With
  `truncated=true`, absence means unknown and must not be presented as zero;
- intercepted/routed connections have exact tuple attribution when
  `unattributed_hits` is zero. Direct traffic
  is sampled by the connection observer only while it is active and a
  long-lived socket can be observed again after an observer pause, so zero
  direct hits do not prove that a condition is unused;
- legacy rule-activity records without condition labels are excluded from
  `total_hits`, and byte-only activity does not affect condition shares;
- one tuple/source produces at most one persisted record per 15-second write
  bucket during normal operation. The small admission map is released when the
  bucket closes. As with the rule timeline, a query boundary can include the
  older part of one boundary aggregate.

## `GET /api/tray`

Returns a lightweight proxied-traffic view for the tray.

Example shape:

```json
{
  "traffic": [
    {"time": "2026-04-15T10:00:00Z", "up_bytes": 0, "down_bytes": 4096}
  ]
}
```

Desktop single-process mode usually bypasses this endpoint and reads tray data directly from the in-process provider. This endpoint mainly exists for diagnostic tray mode.

## `GET /api/events`

Server-Sent Events stream.

Used for real-time log delivery while the UI is actively open.

Event types emitted by the backend:

- `log`
- `webui_status` - a transient state notification sent immediately before an
  automatic or manual WebUI pause; it is not written to history.

## `POST /api/ui/visibility`

Request:

```json
{"active": false}
```

Used by the WebUI when the browser tab becomes hidden or visible again.

Behavior:

- `active=true` marks the UI as actively viewed;
- `active=false` allows the backend to cool down sooner when the tab is hidden or closing.

## WebUI idle control

`GET /api/control/webui/status` remains available even while the WebUI is
disabled. Its response distinguishes an idle WebUI pause from a proxy-service
pause:

```json
{
  "enabled": false,
  "paused": false,
  "auto_paused": true,
  "disabled_reason": "idle",
  "disabled_at": "2026-08-04T12:00:00Z",
  "idle_timeout_seconds": 3600
}
```

While enabled, `idle_deadline_at` contains the current deadline and
`disabled_at`/`disabled_reason` are omitted. `POST /api/control/webui/enable`
enables the UI and establishes a fresh one-hour deadline;
`POST /api/control/webui/disable` disables it with reason `manual`.

The one-hour transition disables only WebUI data/static routes and closes live
UI subscriptions. Runtime routing, WinDivert, proxy tunnels and connection
history continue normally. Health, tray and control endpoints remain
available. A browser navigation to a disabled WebUI receives a small standalone
HTTP 503 explanation page instead of loading the full application.

## Application update API

All three update endpoints are intended for the embedded local WebUI. They
require both a loopback/`localhost` `Host` header and
`X-PitchProx-WebUI: 1`; otherwise they return HTTP `403`. The updater never
checks GitHub in the background.

### `GET /api/update/releases`

Performs one explicit, 30-second-bounded GitHub Releases check and returns at
most the five latest non-draft published releases:

```json
{
  "current_version": "v0.43-rc.6",
  "latest_version": "v0.43",
  "update_available": true,
  "comparison_known": true,
  "checked_at": "2026-08-04T12:00:00Z",
  "releases": [
    {
      "version": "v0.43",
      "name": "pitchProx v0.43",
      "published_at": "2026-08-04T10:00:00Z",
      "prerelease": false,
      "page_url": "https://github.com/agentpitch/prox/releases/tag/v0.43",
      "size": 7340032,
      "installable": true,
      "verification": "manifest"
    }
  ]
}
```

`latest_version` and `update_available` concern the newest stable release;
prereleases still appear in `releases`. A development version may set
`comparison_known=false`. Unusable releases remain visible with
`installable=false` and a bounded human-readable `reason`. The bounded result
is reusable for installation for five minutes, avoiding another download when
the user immediately chooses a version.

### `GET /api/update/status`

Returns the current bounded transaction state:

```json
{
  "phase": "downloading",
  "busy": true,
  "version": "v0.43",
  "message": "Загрузка и проверка файлов…",
  "downloaded_bytes": 1048576,
  "total_bytes": 7340032,
  "updated_at": "2026-08-04T12:01:00Z"
}
```

Phases are `idle`, `checking`, `downloading`, `verifying`, `restarting`,
`completed`, and `failed`. `transaction_id` is present after the handoff plan is
committed; `error` contains a terminal failure. The frontend polls this endpoint
only while an installation requested by that editor is active.

### `POST /api/update/install`

Starts installation of one exact version from the most recent five-release
result:

```json
{"version": "v0.43"}
```

The body is strict JSON, limited to 512 bytes; `version` is limited to 128
bytes. Success returns HTTP `202` with the initial status. HTTP `409` means an
operation or unresolved transaction already exists, the version is not in the
bounded release set, or that release cannot be installed.

The Windows helper verifies hashes and build/runtime compatibility, stages
files beside `pitchProx.exe`, and identifies the parent by PID plus process
creation time. In service mode it additionally verifies the SCM service name
and executable path. It atomically replaces the executable, requires three
matching health responses from the selected build, and only then deletes the
verified rollback copy. Failure restores and health-checks the old build.
Current-format health includes version, PID, and transaction token; the legacy
downgrade path instead requires the exact launched process and an `ok` health
response.

## `POST /api/proxy-test`

Request:

```json
{
  "proxy": {
    "id": "sto",
    "name": "STO",
    "type": "http",
    "address": "10.173.9.1:8888",
    "enabled": true
  },
  "target": "www.google.com:443"
}
```

Behavior:

1. raw TCP connect to proxy;
2. tunnel/connect attempt through proxy to target.

Response fields:

- `ok`
- `proxy_reachable`
- `tunnel_reachable`
- `proxy_type`
- `proxy_address`
- `target`
- `duration_ms`
- `message`

## `POST /api/control/stop`

Requests graceful shutdown.

Desktop mode:
- stops runtime + HTTP + tray.

Service mode:
- signals the service-hosted runtime to stop.

## UI activity semantics

Verbose-log activity and the one-hour WebUI idle timer are separate mechanisms.
`/api/snapshot`, `/api/events` and explicit visibility continue to control the
short verbose-log window.

The idle timer is extended by static WebUI navigation or an application request
marked with `X-PitchProx-WebUI: 1`. EventSource uses `?_ui=1` because browser
EventSource cannot attach that header. Opening SSE counts once; keeping the
connection open or receiving server pings does not. `active=false`, health,
tray, service-control and WebUI-control traffic never extends the deadline.
One shared last-request timestamp means activity from any open tab extends the
deadline, while hiding a different tab cannot shorten it.
