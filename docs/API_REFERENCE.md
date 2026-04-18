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

Returns the full WebUI snapshot.

Fields:

- `connections`
- `logs`
- `traffic`
- `traffic_totals`
- `rule_stats`
- `retention_minutes`

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

Used for real-time log delivery and immediate UI refresh while the UI is open.

Event types emitted by the backend:

- `snapshot`
- `connection`
- `connection_delete`
- `log`

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

This prevents tray polling from accidentally keeping expensive verbose logging enabled all the time.
