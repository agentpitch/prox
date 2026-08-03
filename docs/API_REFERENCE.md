# HTTP API reference

Base address: configured `http.listen`, default `127.0.0.1:18080`.

The API is intended for localhost use only.

## `GET /api/health`

Response:

```json
{"ok": true, "version": "v0.43-rc.1"}
```

`version` is injected at build time. Unversioned developer builds report
`"dev"`.

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

## `POST /api/ui/visibility`

Request:

```json
{"active": false}
```

Used by the WebUI when the browser tab becomes hidden or visible again.

Behavior:

- `active=true` marks the UI as actively viewed;
- `active=false` allows the backend to cool down sooner when the tab is hidden or closing.

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

Only `/api/snapshot` and `/api/events` automatically count as evidence of an
actively viewed UI. An explicit `/api/ui/visibility` request with
`active=true` also marks it active; `active=false` starts the cooldown. Other
API calls do not extend the active period. This prevents tray polling, rule
sparklines, health checks, or control requests from accidentally keeping
verbose log capture enabled.
