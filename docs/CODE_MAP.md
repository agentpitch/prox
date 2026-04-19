# Code map

This file maps concepts to source files.

## Entry point

- `cmd/pitchprox/main.go` - CLI commands, elevation path, desktop mode, service mode, diagnostic tray mode.

## Runtime orchestration

- `internal/app/program.go` - start/stop orchestration for runtime + lightweight loopback WebUI server.
- `internal/app/runtime.go` - owns config store, monitor, flow table, rule engine, direct observer, and selective interception startup.
- `internal/app/direct_observer.go` - UI-driven TCP table observer for direct-bypass connections; it goes dormant when the UI is inactive so direct traffic visibility does not keep periodic TCP snapshots warm in the background.

## Configuration

- `internal/config/model.go` - config schema, defaults, normalization, validation.
- `internal/config/store.go` - portable JSON store next to the executable.

## Rules

- `internal/rules/parser.go` - tokenization and parsing for applications/hosts/ports.
- `internal/rules/matcher.go` - compiled rule engine.
- `internal/rules/matcher_test.go` - syntax and matching tests.

## History and observability

- `internal/history/model.go` - file-backed history record types.
- `internal/history/store.go` - segment-backed history store, batching, flushing, pruning, aggregated queries, bucketed traffic snapshots.
- `internal/monitor/monitor.go` - active in-RAM state, UI activity signaling, SSE publishing, snapshot assembly, bucket sizing, tray view.

## Transparent routing

- `internal/proxy/flowtable.go` - flow identity cache between interception and listener.
- `internal/proxy/sniff.go` - HTTP Host / TLS SNI extraction.
- `internal/proxy/upstream.go` - direct, HTTP CONNECT and SOCKS5 dialers.
- `internal/proxy/test.go` - proxy availability test.
- `internal/proxy/transparent.go` - listener accept loop, route decision, relay, batched byte accounting.

## HTTP API and UI

- `internal/httpapi/server.go` - lightweight localhost API/SSE server and embedded static file server.
- `internal/webui/dist/index.html` - page structure.
- `internal/webui/dist/styles.css` - layout and styling.
- `internal/webui/dist/app.js` - client-side rendering, editors, filters, charts, visibility-aware live mode, and bucket-aware traffic rendering.
- `internal/webui/embed.go` - embeds static assets into the Go binary.

## Windows integration

- `internal/windivert/divert_windows.go` - WinDivert DLL bindings.
- `internal/windivert/engine_windows.go` - interception loop, owner-cache use, flow registration.
- `internal/windivert/packet.go` - packet parsing helpers.
- `internal/win/owner_windows.go` - Windows TCP owner helpers and exe path lookup.
- `internal/win/owner_cache_windows.go` - on-demand owner cache used by the SYN classifier.
- `internal/win/tcp_snapshot_windows.go` - direct-observer TCP snapshot reader with persistent PID-to-exe caching.
- `internal/service/service_windows.go` - Windows Service wrapper.
- `internal/trayapp/tray_windows.go` - tray window, icon drawing, menu, and lightweight remote polling.
- `internal/util/browser_windows.go` - open WebUI in default browser.
- `internal/util/console_windows.go` - hide console on Explorer launch.
- `internal/util/elevate_windows.go` - self-elevation helpers.
- `internal/util/paths.go` - portable config/history paths and overrides.

## Build tags

- `*_windows.go` files contain real Windows implementations.
- `*_stub.go` files contain non-Windows placeholders so syntax and non-Windows tests still run.
