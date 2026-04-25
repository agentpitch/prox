# HTTP API reference

Base address: configured `http.listen`, default `127.0.0.1:18080`.

The API is intended for localhost use only.

## `GET /api/health`

Response:

```json
{"ok": true}
```

## `GET /api/config`

Returns the full current config.

## `PUT /api/config`

Replaces the full config.

Behavior:

- config is normalized;
- config is validated;
- `updated_at` is rewritten server-side;
- the JSON file is written atomically.

Important: changing listen addresses or transparent listener addresses/ports does not hot-rebind existing listeners. The backend logs a restart warning.

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

The backend treats most `/api/*` calls as evidence of active UI and temporarily enables verbose log capture.

Exceptions that do **not** mark the UI active:

- `/api/health`
- `/api/tray`
- `/api/control/stop`
- `/api/ui/visibility`

This prevents tray polling or hidden-tab bookkeeping from accidentally keeping expensive verbose logging enabled all the time.
