# Architecture

## 1. High-level model

pitchProx is a Windows transparent TCP proxy manager written in Go. The program has four logical planes.

### Configuration plane

- loads and saves `pitchProx.config.json` next to the executable;
- normalizes and validates config before use;
- compiles ordered rules into a matcher engine.

### Interception plane

- optionally starts in observer-only mode when all enabled rules are `Direct`;
- otherwise uses a small WinDivert SYN-classifier handle instead of capturing all outbound TCP packets;
- resolves the owning PID and executable path for candidate flows;
- only opens per-flow WinDivert packet handlers for flows that actually need interception;
- redirects only selected traffic to the local transparent listener.

### Routing plane

- accepts redirected TCP sockets;
- reconstructs the original destination from the flow table;
- optionally sniffs hostname from HTTP `Host` or TLS `SNI`;
- matches the request against the ordered rule engine;
- executes `Direct`, `Proxy`, `Chain`, or `Block`.

### Observability + control plane

- serves localhost JSON API and the embedded WebUI;
- maintains lightweight live state for currently open connections;
- persists historical logs, closed connections, proxy traffic and rule activity to SQLite;
- renders a tray icon in desktop mode.

## 2. Process model

### Desktop mode

`pitchProx.exe` runs as one elevated desktop process.

Inside that one process:

- `Runtime` starts either (a) observer-only mode, or (b) selective interception mode with WinDivert + transparent listener;
- `httpapi.Server` serves the WebUI;
- `trayapp.Run()` is started in a goroutine and uses an in-process provider instead of talking to the full snapshot API.

This is the normal daily-use mode.

### Service mode

`pitchProx.exe service` runs under SCM.

Service mode starts:

- runtime;
- localhost HTTP server.

It is intentionally headless. No tray is started from the service because services live in Session 0.

## 3. Core packages

### `cmd/pitchprox`

CLI entry point.

Commands:

- `run`
- `service`
- `install`
- `uninstall`
- `start`
- `stop`
- `open`
- `tray` (diagnostic tray-only mode against a running localhost URL)

### `internal/app`

Application orchestration.

- `Program` starts/stops runtime and HTTP server;
- `Runtime` owns config store, rule engine, monitor, flow table, direct connection observer, and—when needed—the transparent listener and WinDivert engine.

### `internal/config`

- config schema;
- defaults;
- normalization;
- validation;
- portable JSON store.

### `internal/rules`

Compiles Proxifier-style text fields into executable matchers.

### `internal/proxy`

- transparent listener;
- flow table;
- HTTP Host / TLS SNI sniffing;
- direct / HTTP CONNECT / SOCKS5 dialers;
- proxy test;
- relay + batched traffic accounting.

### `internal/windivert`

Windows-only interception loop.

Responsibilities:

- run a lightweight outbound TCP SYN classifier;
- consult owner cache only for new candidate flows;
- fast-path definitive `Direct` flows without opening a relay path;
- open dedicated per-flow WinDivert handlers only for flows that need interception;
- rewrite packets toward the local listener only for those intercepted flows;
- exempt loopback and self-traffic;
- retire per-flow handlers after close or inactivity.

### `internal/win`

Windows owner lookup helpers.

Important change from earlier revisions:

- owner resolution uses an **on-demand TCP owner cache**;
- the process no longer captures every outbound TCP packet globally;
- the hot path now pays full packet interception only for flows that actually need `Proxy / Chain / Block` handling or hostname sniffing.

### `internal/monitor`

Observability bus.

Responsibilities:

- keep only active/open connections in RAM;
- keep a very small recent traffic window in RAM for tray rendering;
- write historical logs/connections/traffic/rule activity into SQLite;
- provide snapshots for WebUI;
- publish SSE log events.

### `internal/history`

SQLite-backed history store.

Persists:

- log entries;
- closed/blocked/error connection records;
- per-second proxied traffic samples;
- per-second rule activity samples.

SQLite database path:

```text
<dir of pitchProx.exe>\pitchProx.history.sqlite
```

### `internal/httpapi`

Serves:

- JSON API;
- SSE event stream;
- embedded WebUI static files.

### `internal/trayapp`

Windows tray implementation.

Responsibilities:

- hidden tray window;
- dynamic icon rendering;
- double-click open;
- context menu;
- lightweight traffic polling in diagnostic mode;
- in-process provider mode in desktop mode.

## 4. Flow of one TCP connection

1. Application creates a new outbound TCP connection.
2. In selective-interception mode, WinDivert sees only the outbound TCP SYN, not every packet on the machine.
3. pitchProx resolves PID/exe from the owner cache.
4. A preflight rule match runs with the information already known at SYN time: PID, executable path, target IP and port.
5. If the result is definitively `Direct`, the SYN is allowed through unchanged and the connection bypasses pitchProx data relaying completely.
6. Otherwise pitchProx opens a dedicated per-flow WinDivert handler and creates a `proxy.Flow` record in `FlowTable`.
7. The first SYN is rewritten to the transparent listener.
8. `proxy.Server` accepts the redirected socket.
9. It looks up the original destination from `FlowTable`.
10. It peeks initial bytes and sniffs hostname where possible.
11. `Runtime.route(...)` compiles a request and asks the full rule engine.
12. The first matching enabled rule wins.
13. One of four outcomes happens:
    - `Direct`
    - `Proxy`
    - `Chain`
    - `Block`
14. If not blocked, bytes are relayed both ways.
15. Accounting updates are batched and attributed to:
    - rule stats;
    - proxy activity when action is `Proxy` or `Chain`.
16. Closed/blocked/error connection history is persisted to SQLite.
17. Open connections remain only in RAM until they close.

## 5. Quiet mode and performance design

The optimized design intentionally separates **core routing** from **heavy observability**.

### Core always-on pieces

- rule engine;
- tiny live tray traffic ring in RAM;
- warning/error logs;
- direct connection observer;
- and only when needed: WinDivert selective interception + transparent listener.

### UI-heavy pieces

- verbose `info/debug` logs;
- large snapshots;
- rich WebUI investigation data.

Verbose logging is only captured while the WebUI is open or recently active. Tray traffic does **not** mark the UI as active.

## 6. Retention model

`Config.RetentionMinutes` is the single source of truth for retention.

It controls:

- historical active-connections view;
- proxy activity graph window;
- rule activity window;
- SQLite pruning horizon.

The default is 7 minutes.

## 7. Data location summary

Portable files next to the executable:

- `pitchProx.config.json`
- `pitchProx.history.sqlite`

Transient/ephemeral:

- tray icon temporary file in `%TEMP%` for the current icon frame.

## 8. Known limits of the current architecture

- TCP only;
- existing connections created before start are not retroactively adopted;
- hostname recovery is strongest for HTTP/TLS;
- no authenticated WebUI;
- service mode is headless;
- no UDP/QUIC/HTTP3.
