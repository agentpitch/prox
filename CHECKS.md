# Verification notes

This archive contains the current optimized baseline with segment-backed history and the single-process desktop mode.

## Cleanup and optimization work included

- tray no longer reads the full `/api/snapshot` feed in desktop mode;
- tray reads a lightweight traffic view and no longer keeps verbose logging permanently enabled;
- connection/log/rule/traffic history is persisted into compact hourly files under `pitchProx.history/` instead of living only in RAM;
- the global all-packets WinDivert path was replaced with a selective SYN classifier plus per-flow interception;
- all-direct rulesets now run in observer-only mode without starting WinDivert at all;
- owner lookup is on-demand instead of hot periodic refresh;
- direct observer now fully sleeps when no active UI client is present and wakes immediately when the UI returns;
- periodic WebUI refreshes can skip historical log payloads, while tab hide/close explicitly marks the UI inactive;
- WebUI traffic snapshots are bucketed on the backend, so long retention windows do not emit or render full per-second series;
- relay accounting is batched instead of writing counters on every copied chunk;
- the embedded WebUI/control plane now uses a lightweight loopback HTTP implementation instead of `net/http`;
- SQLite and `modernc` were removed from the runtime path.

## Checks run in this workspace

These checks were executed successfully:

```text
go test ./...
go mod tidy
node --check internal/webui/dist/app.js
gofmt -w internal/httpapi/server.go internal/trayapp/tray_windows.go internal/history/store.go internal/util/paths.go
go build -trimpath -ldflags="-H=windowsgui -s -w" -o build\pitchProx.exe .\cmd\pitchprox
go build -trimpath -o build\pitchProx-debug.exe .\cmd\pitchprox
```

## Binary-level validation

- stripped `build\pitchProx.exe` size dropped from about `11.9 MB` to about `4.26 MB`;
- `go version -m build\pitchProx.exe` now lists only `golang.org/x/sys` as a non-stdlib dependency;
- `go tool nm -size build\pitchProx-debug.exe` no longer shows:
  - `crypto/internal/fips140/drbg.memory`
  - `modernc.org/sqlite`
  - `modernc.org/libc`
  - `net/http`
  - `crypto/tls`

## What was not executed here

- elevated end-to-end runtime execution of `pitchProx.exe run`;
- WinDivert interception against a live Windows network stack;
- Windows tray interaction with the real shell;
- Windows Service installation/start/stop.

## Recommended Windows verification

1. Put `WinDivert.dll` and `WinDivert64.sys` next to `pitchProx.exe`.
2. Build and run `build\pitchProx.exe`.
3. Verify:

- one `pitchProx.exe` process in desktop mode;
- tray icon appears and opens WebUI on double click;
- `pitchProx.config.json` and `pitchProx.history\` appear next to the executable;
- rule matching works for `Direct / Proxy / Chain / Block`;
- proxy activity, connection history, and logs continue to work after long uptime;
- hiding or closing the WebUI allows the runtime to return to a colder quiet mode;
- idle memory is materially lower than older builds because the binary no longer links `net/http`/TLS or SQLite.
