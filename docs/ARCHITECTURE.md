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
- lazily opens one shared redirector while at least one flow actually needs interception;
- closes that redirector immediately when the last selected flow is retired;
- redirects only selected traffic to the local transparent listener.

### Routing plane

- accepts redirected TCP sockets;
- reconstructs the original destination from the flow table;
- optionally sniffs hostname from HTTP `Host` or TLS `SNI`;
- matches the request against the ordered rule engine;
- executes `Direct`, `Proxy`, `Chain`, or `Block`.

### Observability + control plane

- serves localhost JSON API and the embedded WebUI through a lightweight loopback HTTP implementation;
- maintains lightweight live state for currently open connections;
- persists historical logs, closed connections, proxy traffic and rule activity into compact hourly file segments;
- renders a tray icon in desktop mode;
- lets the direct observer go dormant again when no active UI client remains;
- compacts WebUI traffic snapshots into bounded time buckets before serializing them.
- checks GitHub Releases only on explicit user request and performs a verified,
  rollback-capable executable handoff through a short-lived helper.

## 2. Process model

### Desktop mode

`pitchProx.exe` runs as one elevated desktop process.

Inside that one process:

- `Runtime` starts either (a) observer-only mode, or (b) selective interception mode with WinDivert + transparent listener;
- `httpapi.Server` serves the WebUI without `net/http` or TLS baggage;
- `trayapp.Run()` is started in a goroutine and uses an in-process provider instead of talking to the full snapshot API.

This is the normal daily-use mode.

During an accepted application update, the current executable creates one
verified helper copy beside itself. The helper is a temporary process, not a
resident updater service. It takes over a cross-process lock, waits for an
explicit full-identity permission record, replaces the executable, and exits
after the selected build or the restored old build passes health checks.

### Service mode

`pitchProx.exe service` runs under SCM.

Service mode starts:

- runtime;
- localhost lightweight HTTP server.

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
- `update-helper --plan <path>` (hidden internal handoff mode; not a user command)

### `internal/app`

Application orchestration.

- `Program` starts/stops runtime and the lightweight loopback WebUI server;
- `Runtime` owns config store, rule engine, monitor, flow table, direct connection observer, and—when needed—the transparent listener and WinDivert engine.

### `internal/config`

- config schema;
- defaults;
- normalization;
- validation;
- portable JSON store.

### `internal/rules`

Compiles Proxifier-style text fields into executable matchers.
Along with the winning rule, a decision carries the first matching authored
alternative for application, host and port. These labels are observational
metadata only; the raw multi-value rule fields and first-rule-wins routing
semantics are unchanged.

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
- open one shared packet redirector lazily while intercepted flows exist;
- rewrite only packets matching an entry in the bounded flow table and reinject other captured packets unchanged;
- exempt loopback and self-traffic;
- retire unopened flows after inactivity and close the shared redirector as soon as the table becomes empty.

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
- write historical logs/connections/traffic/rule activity into hourly file segments;
- provide snapshots for WebUI;
- publish SSE log events.

### `internal/history`

Segment-backed history store.

Persists:

- log entries;
- closed/blocked/error connection records;
- per-second proxied traffic samples;
- 15-second rule activity aggregates, optionally carrying one bounded matched
  application/host/port tuple and its observation source. Condition details
  have a 256-key admission budget per bucket and remain coalesced until the
  bucket closes, preventing snapshot frequency from amplifying disk writes.

History store path:

```text
<dir of pitchProx.exe>\pitchProx.history\
```

### `internal/httpapi`

Serves:

- JSON API;
- SSE event stream;
- embedded WebUI static files.

### `internal/updater`

On-demand GitHub release discovery and Windows executable replacement.

- keeps at most five releases in a five-minute in-memory cache;
- uses no background network polling and one bounded install goroutine only
  after an explicit request;
- cross-checks GitHub asset digests, the checksum file, the clean build
  manifest, PE architecture, and installed WinDivert hashes;
- supports a restricted pre-manifest downgrade only when the selected ZIP's
  runtime hashes exactly match the installed DLL and driver;
- binds a handoff to PID plus process creation time and, in service mode, the
  exact SCM service/image identity;
- transfers a two-byte file-lock baton to one exact helper process and requires
  observing/acquired/proceeding acknowledgements bound to the transaction;
- uses `ReplaceFileW`, verified backup/recovery copies, and three matching
  health probes before deleting the old executable;
- reconciles interrupted fixed-path transactions at startup/status access and
  quarantines ambiguous state instead of guessing or discarding rollback data.

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
6. Otherwise pitchProx creates a `proxy.Flow` record and lazily opens the shared redirector if it is not already active.
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
    - the first matching application/host/port alternatives for each newly
      observed TCP connection;
    - proxy activity when action is `Proxy` or `Chain`.
16. Closed/blocked/error connection history is persisted to the file-backed history store.
17. Open connections remain only in RAM until they close.
18. When the final intercepted connection closes, the flow table releases high-water capacity and the shared redirector is closed.

## 5. Quiet mode and performance design

The optimized design intentionally separates **core routing** from **heavy observability**.

### Core always-on pieces

- rule engine;
- tiny live tray traffic ring in RAM;
- warning/error logs;
- direct connection observer, but only while the UI is actively viewed;
- and only when needed: WinDivert selective interception + transparent listener.

### UI-heavy pieces

- verbose `info/debug` logs;
- large snapshots;
- rich WebUI investigation data.

Verbose logging is only captured while the WebUI is open or recently active. Tray traffic does **not** mark the UI as active.
When the browser tab is hidden or closing, the frontend explicitly marks the UI inactive so the backend can return to the colder quiet-mode behavior sooner.
Traffic history for the WebUI is bucketed before it leaves the backend, so long retention windows do not require building or shipping giant per-second arrays.
Condition details are queried lazily only while a rule is inspected. The query
reverse-scans retained rule segments into fixed-cap transient maps (1,024 tuple
groups and 512 marginal values per dimension), returns top-N tuples, and then
releases all query memory. It never creates a Cartesian product of rule
alternatives and adds no always-running goroutine or cache.
Collection itself admits at most 1,024 distinct detailed keys per flush interval
within the existing 4,096-entry rule pending-map limit. Excess cardinality is
folded into a source-aware overflow aggregate: ordinary rule connection totals
remain correct while the detail response reports unattributed hits and marks
its affected summaries as truncated.

### Long-running resource lifecycle

- history flushes are driven by pending work rather than a permanent ticker;
- failed writes use a 30-second retry interval and bounded emergency queues, with a diagnostic counter for discarded overflow;
- startup truncates only an incomplete JSONL tail, while malformed complete lines are skipped without hiding valid neighboring records;
- dropped-connection pagination, deletion and size trimming stream files instead of loading the full log into RAM;
- PID-to-executable cache entries use PID plus process creation time and expire during on-demand owner refresh; the separate WebUI TCP-snapshot cache is released as soon as its observer becomes dormant;
- flow maps compact after bounded deletions, relay connection maps compact geometrically while a burst drains even if one socket remains open, and the bounded HTTP map resets after draining;
- condition-detail admission and query maps are bounded; their 15-second admission map is discarded after the bucket is persisted, while overflow keeps rule totals without retaining arbitrary labels;
- a dormant Direct observer waits on the monitor wake channel rather than periodically polling UI state;
- the flow cleanup timer is armed only while pending flow records exist;
- forced heap release is conditional and infrequent rather than an unconditional periodic GC;
- configuration changes that require a routing restart are activated before being committed to disk and roll back to the previous running configuration if activation fails.
- release checks allocate only for the explicit request; install/download
  buffers, HTTP bodies, release lists, helper handles, and timers are capped and
  released. Startup reconciliation has a finite retry schedule and then exits.

## 6. Retention model

`Config.RetentionMinutes` is the single source of truth for retention.

It controls:

- historical active-connections view;
- proxy activity graph window;
- rule activity window;
- rule condition-activity window;
- segment pruning horizon.

The default is 7 minutes.

History remains a compact hourly JSONL segment store. SQLite/WAL is intentionally not used: the store has one in-process writer, and WAL would add a database runtime and background/checkpoint work without solving a demonstrated concurrency requirement.

The WebUI `Новые` connection tab reuses the retained connection segments. It reports application/address/port signatures first seen during the last minute, but only when the selected retention window is longer than one minute so there is an earlier baseline inside the same window.

## 7. Data location summary

Portable files next to the executable:

- `pitchProx.config.json`
- `pitchProx.history\`

During an update, fixed-name transaction files may briefly appear beside the
executable (`.pitchProx-update-*`). Success removes stage, rollback, plan,
acknowledgement, and permission files; a single zero-byte lock file may remain
for safe path-stable reuse. On interruption, verified rollback material is kept
until a later bounded reconciliation can determine the state safely.

Transient/ephemeral:

- tray icon temporary file in `%TEMP%` for the current icon frame.

## 8. Known limits of the current architecture

- TCP only;
- existing connections created before start are not retroactively adopted;
- hostname recovery is strongest for HTTP/TLS;
- no authenticated WebUI;
- HTTP is intentionally loopback-only;
- service mode is headless;
- no UDP/QUIC/HTTP3.
