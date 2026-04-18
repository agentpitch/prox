# Verification notes

This archive contains the optimized baseline with SQLite-backed history and the current single-process desktop mode.

## Cleanup and optimization work included

- tray no longer reads the full `/api/snapshot` feed in desktop mode;
- tray reads a lightweight traffic view and no longer keeps verbose logging permanently enabled;
- connection/log/rule/traffic history is persisted in SQLite (`pitchProx.history.sqlite`) instead of living only in RAM;
- the global all-packets WinDivert path was replaced with a selective SYN classifier plus per-flow interception;
- all-direct rulesets now run in observer-only mode without starting WinDivert at all;
- owner lookup is on-demand instead of hot periodic refresh;
- relay accounting is batched instead of writing counters on every copied chunk;
- flow-table keys no longer allocate formatted strings;
- stale WebUI and tray helper code paths from earlier revisions were removed.

## Checks run in the container

These checks were executed successfully:

```text
go test ./internal/rules ./internal/config
node --check internal/webui/dist/app.js
gofmt on modified Go files
```

## What could not be executed in the container

The container is not Windows and has no network access for fetching new Go modules, so the following were not executed here:

- `go mod tidy` for the new SQLite dependency;
- full `go test ./...` after adding SQLite;
- `go build` and runtime execution on a Windows kernel;
- WinDivert interception;
- Windows tray integration with the real shell;
- Windows Service installation/start/stop.

## Recommended Windows verification after unpacking

1. Put `WinDivert.dll` and `WinDivert64.sys` next to `pitchProx.exe`.
2. Run:

```powershell
go mod tidy
go build -trimpath -ldflags="-s -w" -o build\pitchProx.exe .\cmd\pitchprox
```

3. Desktop mode:

```powershell
build\pitchProx.exe
```

4. Verify:

- one `pitchProx.exe` process in desktop mode;
- tray icon appears and opens WebUI on double click;
- `pitchProx.config.json` and `pitchProx.history.sqlite` appear next to the executable;
- rule matching works for `Direct / Proxy / Chain / Block`;
- proxy activity, connection history and logs continue to work after long uptime;
- idle CPU is lower than earlier builds because no full snapshot is polled by tray.

5. Optional service checks:

```powershell
build\pitchProx.exe install
build\pitchProx.exe start
build\pitchProx.exe stop
build\pitchProx.exe uninstall
```
