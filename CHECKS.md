# Verification notes

The September 2026 background-resource audit, measured hot paths, regression
checks and remaining live-runtime verification are recorded in
[RESOURCE_AUDIT_2026-09-23.md](docs/RESOURCE_AUDIT_2026-09-23.md).

Headless control is documented in [AGENT_CLI.md](docs/AGENT_CLI.md). Its tests
cover strict JSON, revision conflicts, no-op apply, rule positioning, inactive
WebUI access, mutation serialization with the updater, HTTP listener handoff,
and rollback after bind/runtime/config-save failures. A disposable Windows
GUI-subsystem EXE was also exercised with redirected stdin/stdout/stderr through
all CLI commands, including runtime restart and HTTP rebind with an unchanged PID.

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
- the embedded WebUI/control plane uses a lightweight loopback HTTP
  implementation; the explicit GitHub updater and short-lived `ctl` client
  use `net/http`, with no idle network polling;
- SQLite and `modernc` were removed from the runtime path.
- history recovery, retry and pending-memory behavior are bounded for long-running disk-error scenarios;
- process-path caches validate PID reuse with process creation time;
- flow/connection maps geometrically release high-water capacity while bursts drain, even if a long-lived connection remains;
- the WebUI-only PID/path snapshot cache is released when the Direct observer becomes dormant;
- per-condition history is coalesced once per 15-second bucket with a 256-key admission budget, so frequent WebUI snapshots cannot amplify JSONL writes;
- IPv6 extension headers and multi-record TLS ClientHello/SNI are parsed with strict work and size bounds;
- runtime config activation rolls back if a required listener/interception restart fails.

## v0.43 release gate

A publishable v0.43 candidate is prepared only from a committed clean working
tree with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\package-release.ps1 -Version v0.43 -DownloadWinDivertArchive
```

The script fails immediately on an uncommitted tree unless `-AllowDirty` is
explicitly supplied for a disposable test build. `-SkipChecks` is rejected
unless `-AllowDirty` is also present. A publishable candidate always requires
and executes:

```text
Node.js v22.17.0
node --check internal/webui/dist/rules-ui.js
node --check internal/webui/dist/app.js
node --test internal/webui/rules_ui_test.js internal/webui/lifecycle_test.js
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

- for an updater-compatible local candidate and in CI, downloads or accepts an
  explicitly supplied copy of the pinned official archive, then verifies its
  archive hash, x64 DLL, driver, and LICENSE; temporary extraction stays inside
  the candidate tree and is removed before packaging finishes;
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

- `go version -m` lists only `golang.org/x/sys` as a non-stdlib dependency;
- SQLite/`modernc` remain absent from the runtime and symbol table;
- `net/http` and `crypto/tls` are now intentionally linked by the on-demand
  GitHub updater. The custom WebUI server still does not use them, and no
  updater network request runs until the user presses **Проверить обновления**;
- executable size is no longer compared with the pre-updater 4.26 MB baseline.
  The exact size and SHA-256 of each candidate are recorded in
  `pitchProx-build-manifest.json` and `pitchProx-windows-amd64.sha256`;
- `go tool nm -size` of an unstripped diagnostic build must still not show:
  - `crypto/internal/fips140/drbg.memory`
  - `modernc.org/sqlite`
  - `modernc.org/libc`

## What was not executed here

- elevated end-to-end runtime execution of `pitchProx.exe run`;
- WinDivert interception against a live Windows network stack;
- Windows tray interaction with the real shell;
- Windows Service installation/start/stop;
- elevated end-to-end updater handoff through helper, SCM replacement, health
  confirmation, and forced rollback. Unit tests exercise real Windows
  `LockFileEx`/`ReplaceFileW`, but not a live installed service.

## Recommended Windows verification

1. Put `WinDivert.dll` and `WinDivert64.sys` next to `pitchProx.exe`.
2. Build and run `build\pitchProx.exe`.
3. Verify:

- one `pitchProx.exe` process in desktop mode;
- tray icon appears and opens WebUI on double click;
- `pitchProx.config.json` and `pitchProx.history\` appear next to the executable;
- rule matching works for `Direct / Proxy / Chain / Block`;
- clipboard export of all or selected rules round-trips through the import
  textarea and preview; the left-side file download/load actions produce the
  same JSON and validation result;
- typing or pasting while a file read is pending cannot be overwritten by that
  stale read, and a complete config above the 8 MiB service limit is rejected
  client-side without a partial save;
- proxy activity, connection history, and logs continue to work after long uptime;
- hiding or closing the WebUI allows the runtime to return to a colder quiet mode;
- WebUI auto-pauses after one hour without browser requests, control/tray polling and a long-lived SSE do not prevent it, and the loaded page reports that routing continues; right-clicking the tray must switch **Отключить WebUI** to **Включить WebUI**, while the full-service action is labelled **Приостановить работу**;
- Settings performs no release request until explicitly asked, shows exactly the
  latest five GitHub releases, and leaves no status timer after the dialog closes;
- in a controlled disposable installation, update to a current-format release,
  verify exact-version restart and cleanup, then simulate a failed new start and
  confirm that the verified old executable is restored; separately validate
  service-mode SCM handoff;
- idle memory remains materially lower than older builds because SQLite is
  absent and both observability and updater work are dormant/bounded when idle,
  even though the updater now intentionally links `net/http`/TLS.

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

## Isolated updater verification on 2026-08-04

An isolated pre-release test build was built and launched unelevated with a disposable
config/history on `127.0.0.1:18183`, while the existing application remained on
`127.0.0.1:18080` with the same PID. Browser automation confirmed:

- existing-rule condition activity opens expanded above editable fields;
- the rule-enabled control stays on the name row at desktop width;
- Settings makes no release request before the explicit button is pressed;
- the real response contains exactly v0.41–v0.37, all five compatible legacy
  releases, and the downgrade warning explains the one-way updater limitation;
- closing the dialog/browser leaves no console errors or updater polling.

The disposable candidate then performed a real GitHub-backed desktop downgrade
to v0.41. The original isolated PID `16112` was replaced by PID `17476`; the
new target SHA-256 exactly matched the published v0.41 checksum, legacy health
passed, and the transaction state reported `completed`. Plan, stage, backup,
recovery, acknowledgement, and permission files were gone. Only the single
fixed-name state file, zero-byte reusable lock, and one fixed-name legacy helper
remained; the helper is registered for best-effort deletion at reboot and
cannot accumulate under versioned names. The isolated v0.41 process was then
stopped, and the production `v0.43-rc.3` health endpoint/PID were unchanged.

This verifies the real download, legacy compatibility gate, desktop lock
handoff, executable replacement, restart, health confirmation, and successful
cleanup path. It does not replace the still-recommended elevated WinDivert,
forced-rollback, or installed-SCM end-to-end tests listed above.
