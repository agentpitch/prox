# Historical CPU diagnostics (2026-04-15)

This document preserves an earlier live CPU investigation that was performed against
`myprox_project_v23_optimized_sqlite` on Windows x64 before the project was later
renamed to **pitchProx** and before subsequent runtime refactors.

## Current status of the report

The report is **still useful**, but it should be read as a **historical design note**,
not as a current benchmark.

What remains valuable:

- it demonstrated that the steady CPU floor was dominated by **kernel-mode** work,
  not by WebUI rendering or SQLite activity;
- it showed that increasing the owner-cache refresh interval was **not** the main fix;
- it identified the real architectural issue: **`Direct` traffic was still taking the
  full transparent interception and relay path**;
- it justified later optimizations such as:
  - the `Direct` fast-path;
  - observer-only mode when all enabled rules resolve to `Direct`;
  - reducing tray/UI work when the WebUI is inactive;
  - moving historical observability data out of RAM.

What is partially stale:

- process names, paths, and file names in the report still use the earlier
  `myprox` naming;
- exact CPU percentages and memory figures were measured on a specific host and on
  an older runtime revision;
- some implementation details referenced there may have been refactored later.

## Why it is kept

The report is preserved because it captures the reasoning behind several important
performance decisions. If future work revisits CPU usage, this report is the best
historical explanation of **why `Direct` must be a real bypass path whenever that can
be decided safely**.

## Original report

# CPU Diagnostics Report

Date: 2026-04-15
Project: `myprox_project_v23_optimized_sqlite`
Platform: Windows x64

## Scope

This report captures the live CPU diagnostics performed against a running `myprox.exe`
instance after a successful rebuild and restart. The goal was to identify the real
source of unnecessary CPU usage, not just list possible suspects from static code
inspection.

## Runtime state during diagnostics

Configuration at measurement time:

- `retention_minutes = 7`
- no proxies
- no chains
- only two rules:
  - `Localhost / This PC` -> `Direct`
  - `Default` -> `Direct`

Runtime observations:

- `myprox.exe` was alive and `/api/health` returned `{"ok":true}`
- WebUI was not actively open during the main CPU measurements
- `myprox.exe` had the expected listeners:
  - `127.0.0.1:18080` for WebUI
  - `0.0.0.0:26001` and `:::26001` for the transparent listener
- `WinDivert.dll` and `WinDivert64.sys` were present next to `build\myprox.exe`

## Measurement summary

### 1. Baseline CPU with default runtime behavior

Measurement window: 30 seconds

- logical processors: `2`
- CPU delta: `1.266s` over `30s`
- average total machine CPU consumed by `myprox.exe`: `2.11%`
- equivalent load on one logical CPU: about `4.22%`
- working set stayed around `21.1 MB`

Dominant threads during the baseline sample:

- thread `11384`: `0.875s` CPU delta
- thread `17512`: `0.2031s`
- thread `18308`: `0.1406s`
- other threads were substantially lower

Interpretation:

- the cost is concentrated mostly in one hot thread
- this does not look like random bursty UI rendering or SQLite query spikes
- it looks like one always-on traffic/interception path doing steady work

### 2. Kernel vs user mode split

Measurement window: 20 seconds

- kernel mode delta: `0.9844s`
- user mode delta: `0.0312s`
- kernel share of process CPU: `96.9%`
- user share of process CPU: `3.1%`

Interpretation:

- the observed CPU is overwhelmingly kernel-side
- this strongly points to packet interception / socket / reinjection overhead
- this does **not** look like a primarily SQLite, JSON, WebUI, or JS-rendering problem

### 3. Process I/O profile

Average process I/O rates during sampling:

- `IO Read Bytes/sec`: `0`
- `IO Write Bytes/sec`: `1215.57`
- `IO Other Bytes/sec`: `9756.28`
- `IO Data Bytes/sec`: `1215.57`

Interpretation:

- payload I/O volume was low
- CPU remained measurable despite low data throughput
- this again points to per-packet/per-connection interception overhead rather than
  large payload copying or heavy SQLite writes

### 4. System TCP activity during sampling

Measured TCP segment rates:

- `TCPv4 Segments/sec` average: `58.9`
- `TCPv4 Segments Sent/sec` average: `29.58`
- `TCPv4 Segments Received/sec` average: `29.32`
- `TCPv6` segment counters were effectively `0`

System TCP table size:

- total TCP entries: `52`
- established: `12`
- listen: `24`

Interpretation:

- the machine was not under extreme TCP load
- even at modest packet rates, `myprox.exe` still showed a steady CPU floor

### 5. Live snapshot evidence

An `/api/snapshot` sample showed:

- `connection_count = 11`
- `log_count = 0`
- `traffic_samples = 0`
- `rule_stats = 1`

Representative connections seen in the snapshot:

- `codex.exe` -> `chatgpt.com:443` -> `Direct`
- `codex.exe` -> `ab.chatgpt.com:443` -> `Direct`
- `msedge.exe` -> `ws.chatgpt.com:443` -> `Direct`
- `svchost.exe` -> `login.live.com:443` -> `Direct`
- `taskhostw.exe` -> `settings-win.data.microsoft.com:443` -> `Direct`

Interpretation:

- WebUI was not causing the measured baseline CPU
- proxy traffic aggregation was not causing the measured baseline CPU
- the active work was plain `Direct` traffic still flowing through MyProx

## Controlled experiment: owner-cache refresh interval

### Hypothesis

One possible explanation was the background owner-cache refresh loop in
`internal/win/owner_cache_windows.go`, which rebuilds TCP owner maps on a timer.

By default:

- refresh interval: `250ms`

### Diagnostic change

A temporary diagnostic override was added in:

- `internal/windivert/engine_windows.go`

Environment variable:

- `MYPROX_OWNER_CACHE_MS`

This allows running the same binary with a larger refresh interval without changing
the default production behavior.

### Test

The process was restarted with:

- `MYPROX_OWNER_CACHE_MS=2000`

Then the same CPU measurements were repeated.

Results with `2000ms` refresh interval:

- CPU delta over 30s: `1.281s`
- average total machine CPU: `2.14%`
- kernel mode over 20s: `0.8594s`
- user mode over 20s: `0.0469s`
- kernel share: `94.8%`

Conclusion from the experiment:

- increasing owner-cache refresh interval by `8x` did **not** materially reduce CPU
- therefore owner-cache refresh is **not** the primary cause of the observed steady
  CPU floor on this host
- owner-cache still has a cost, but it is secondary in the current workload

## Code-path correlation

The live measurements match the following runtime design:

### A. WinDivert intercepts all outbound TCP

Relevant file:

- `internal/windivert/engine_windows.go`

Important behavior:

- `WinDivertOpen("outbound and tcp", ...)` captures all outbound TCP packets
- for each outbound non-local SYN, MyProx resolves the owner, registers a flow,
  rewrites the destination to the transparent listener, recalculates checksums,
  and reinjects the packet

This is a kernel-heavy path, which matches the measured `96.9%` kernel CPU split.

### B. `Direct` is not a bypass path

Relevant file:

- `internal/proxy/transparent.go`

Important behavior:

- the transparent listener accepts the redirected connection
- it performs route resolution
- if the rule result is `Direct`, it still opens a new upstream socket
- the payload is then relayed through MyProx in userland

This means `Direct` still pays for:

- WinDivert capture
- packet rewrite + reinjection
- local listener accept
- new outbound dial from MyProx
- relay copy goroutines

In other words, `Direct` currently means "relay directly", not "bypass MyProx".

### C. UI and SQLite are secondary for the baseline issue

Relevant files:

- `internal/monitor/monitor.go`
- `internal/history/store.go`
- `internal/httpapi/server.go`
- `internal/webui/dist/app.js`

Observed facts:

- WebUI was not open during the baseline measurement
- snapshot `log_count` was `0`
- `traffic_samples` was `0`
- the CPU was mostly kernel mode, not user mode

This rules out UI snapshot rendering and SQLite aggregation as the primary baseline
cause, although they can still matter when the WebUI is open.

## Root cause

The primary cause of unnecessary CPU usage is architectural:

- MyProx intercepts all outbound TCP with WinDivert at the network layer
- even connections that ultimately resolve to `Direct` are redirected into the
  local transparent listener and relayed through MyProx

Because of that, the program pays a continuous interception and relay tax even in a
configuration where all useful traffic is effectively `Direct`.

This is the reason the process retains a measurable CPU floor even when:

- no proxy/chain is configured
- WebUI is closed
- payload throughput is modest
- SQLite activity is low

## Secondary contributors

These are real costs, but they were not the dominant cause in this session:

- owner-cache periodic refresh in `internal/win/owner_cache_windows.go`
- WebUI snapshot aggregation through `monitor.Snapshot()` and `history.Snapshot()`
- SQLite flush loop running once per second
- per-chunk accounting and traffic recorder locking in the relay path
- tray polling and tray icon regeneration

## Optimization priorities

### Highest priority

Implement a true fast-path for `Direct`.

Desired outcome:

- if a new connection can be determined to be `Direct` without hostname sniffing,
  do not redirect it into the transparent listener
  do not create a userland relay for it

This is the optimization most likely to remove the measured steady CPU floor.

### Next priority

Introduce an interception mode that avoids full transparent routing when the config
is effectively all-`Direct`.

Examples:

- default-direct mode
- interception only for rules that actually need proxy/chain/block processing

### Medium priority

Reduce secondary costs:

- make owner-cache refresh adaptive or event-driven instead of fixed-interval
- cache WebUI snapshot results
- reduce per-chunk accounting overhead in relay code
- avoid work for tray/UI when not in active use

## Final conclusion

The diagnostics do **not** support the theory that SQLite or the WebUI are the main
reason for the current idle-ish CPU burn.

The diagnostics **do** support the conclusion that the current interception model is
the main cause:

- MyProx processes all outbound TCP
- `Direct` traffic still takes the full transparent interception path
- the measured CPU is predominantly kernel-mode, which is exactly what this design
  would produce

## Notes

- During diagnostics, a temporary runtime override hook for the owner-cache interval
  was added via `MYPROX_OWNER_CACHE_MS`.
- After the experiment, the process was restarted back in default runtime mode.

