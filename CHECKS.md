# Verification notes

This archive contains the current optimized baseline with segment-backed history and the single-process desktop mode.

## Cleanup and optimization work included

- tray no longer reads the full `/api/snapshot` feed in desktop mode;
- tray reads a lightweight traffic view and no longer keeps verbose logging permanently enabled;
- connection/log/rule/traffic history is persisted into compact hourly files under `pitchProx.history/` instead of living only in RAM;
- the global always-on all-packets WinDivert path was replaced with a selective SYN classifier plus a shared redirector that exists only while intercepted flows are active;
- all-direct rulesets now run in observer-only mode without starting WinDivert at all;
- owner lookup is on-demand instead of hot periodic refresh;
- direct observer now fully sleeps when no active UI client is present and wakes immediately when the UI returns;
- periodic WebUI refreshes can skip historical log payloads, while tab hide/close explicitly marks the UI inactive;
- WebUI traffic snapshots are bucketed on the backend, so long retention windows do not emit or render full per-second series;
- relay accounting is batched instead of writing counters on every copied chunk;
- the embedded WebUI/control plane now uses a lightweight loopback HTTP implementation instead of `net/http`;
- SQLite and `modernc` were removed from the runtime path.
- history recovery, retry and pending-memory behavior are bounded for long-running disk-error scenarios;
- process-path caches validate PID reuse with process creation time;
- flow/connection maps geometrically release high-water capacity while bursts drain, even if a long-lived connection remains;
- the WebUI-only PID/path snapshot cache is released when the Direct observer becomes dormant;
- per-condition history is coalesced once per 15-second bucket with a 256-key admission budget, so frequent WebUI snapshots cannot amplify JSONL writes;
- IPv6 extension headers and multi-record TLS ClientHello/SNI are parsed with strict work and size bounds;
- runtime config activation rolls back if a required listener/interception restart fails.

## v0.43 release-candidate gate

A publishable v0.43 candidate is prepared only from a committed clean working
tree with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\package-release.ps1 -Version v0.43-rc.2
```

The script fails immediately on an uncommitted tree unless `-AllowDirty` is
explicitly supplied for a disposable test build. `-SkipChecks` is rejected
unless `-AllowDirty` is also present. A publishable candidate always requires
and executes:

```text
Node.js v22.17.0
node --check internal/webui/dist/rules-ui.js
node --check internal/webui/dist/app.js
node --test internal/webui/rules_ui_test.js
go1.26.5 windows/amd64, GOAMD64=v1, CGO_ENABLED=0
GOWORK=off, GOENV=off, default GOEXPERIMENT/GOFIPS140, exact repository go.mod
go mod download + verify with GOFLAGS=-mod=readonly
go test -mod=readonly -count=1 -cover ./...
go vet -mod=readonly ./...
git diff --check and git show --check HEAD
physical working-tree EOLs match .gitattributes
go build -mod=readonly -trimpath -buildvcs=true with the Windows GUI subsystem
```

Release packaging additionally:

- locally reuses and verifies the exact root WinDivert 2.2.2 x64 DLL/driver plus the tracked upstream LICENSE, without temporary archive extraction;
- in CI, explicitly downloads and verifies the official archive before verifying its x64 DLL, driver, and LICENSE;
- includes WinDivert, Go, and `golang.org/x/sys` licenses plus `THIRD_PARTY_NOTICES.md`;
- statically verifies the exact injected version in the binary, and requires `go version -m` to report the intended target, commit, and `vcs.modified=false` for a clean candidate;
- writes `pitchProx-build-manifest.json` with source, toolchain, target, dependency, license, and executable hashes;
- emits a ZIP with ordinally sorted entries and the source-commit timestamp, followed by an LF-encoded SHA-256 file verified again by the release job;
- refuses candidate cleanup when the output path or any existing child is a junction/symlink, and rejects mismatched tracked-text EOLs so embedded WebUI bytes stay stable.

The manifest and `pitchProx-windows-amd64.sha256` next to each candidate are the
authoritative record for that particular artifact. The release pipeline does
not start the executable, load WinDivert, stop the already running application,
or overwrite `build\pitchProx.exe`.

## Earlier checks run in this workspace

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
- WebUI auto-pauses after one hour without browser requests, control/tray polling and a long-lived SSE do not prevent it, the loaded page reports that routing continues, and **Управление** in the tray enables it again;
- idle memory is materially lower than older builds because the binary no longer links `net/http`/TLS or SQLite.

## Audit verification on 2026-07-28

The long-running resource audit in `docs/CODE_AUDIT_2026-07-28.md` was validated after all code and module-path changes with:

```text
go test -count=5 ./...
go vet ./...
node --check internal/webui/dist/app.js
go build -trimpath -ldflags="-H=windowsgui -s -w" -o build\pitchProx-review.exe .\cmd\pitchprox
```

Result:

- all packages passed five consecutive test runs;
- the Windows handle-churn test passed repeated 1000-connection cycles;
- `go vet` reported no findings;
- module metadata now reports `github.com/agentpitch/prox`;
- `build\pitchProx-review.exe` size: `4,580,864` bytes;
- SHA-256: `C31B2B51AA056BE7537CAC1189058A1B57CD78369BD139AF1852D7654567B3D3`.

The review binary was deliberately written under a different filename. The already running elevated `pitchProx.exe` process was not stopped, replaced, or used for WinDivert end-to-end testing.
