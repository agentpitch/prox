# pitchProx

pitchProx is a Windows transparent TCP proxy manager written in Go. It combines:

- a privileged runtime that uses WinDivert only where interception is actually required;
- a local transparent listener that handles only `Proxy / Chain / Block` flows and hostname-dependent `Direct` decisions;
- a localhost WebUI for configuration and observability;
- a Windows tray icon with live proxied traffic activity;
- segment-backed file history so connection/log/rule history does not stay in RAM.

This repository is intended to be **portable**: the runtime configuration is stored next to `pitchProx.exe` as `pitchProx.config.json`, and runtime history is stored next to it as `pitchProx.history/`.

Legacy compatibility:
- if `myprox.config.json` exists next to the executable, pitchProx will copy it into the new `pitchProx.*` filename on first start;
- legacy `myprox.history.sqlite` files are left untouched; new builds write history into `pitchProx.history/`;
- legacy `MYPROX_CONFIG`, `MYPROX_HISTORY`, and `MYPROX_DISABLE_TRAY` environment variables are still honored.

## What the program does

pitchProx watches new outbound TCP connections, determines which process created them, matches the connection against an ordered ruleset, and then chooses one of four actions. In the optimized runtime, connections that are definitively `Direct` are bypassed without entering the local relay path.

- `Direct` - connect directly to the original destination.
- `Proxy` - connect through one proxy profile.
- `Chain` - connect through a sequence of proxy profiles.
- `Block` - deny the connection.

The rules use Proxifier-style text fields:

- `Applications`
- `Target hosts`
- `Target ports`

Rules are evaluated **top to bottom**. The first matching enabled rule wins.

## Current process model

There are two supported runtime modes.

### Desktop mode

Recommended for day-to-day use.

```powershell
pitchProx.exe
```

Desktop mode runs as **one elevated process** and contains:

- selective WinDivert interception
- transparent listener (only when the current ruleset actually needs interception)
- localhost WebUI server
- tray icon

No second `pitchProx.exe tray` helper is required in this mode.

### Service mode

Optional for background/system use.

```powershell
pitchProx.exe install
pitchProx.exe start
```

In service mode the process is headless. The service does not display a tray icon because Windows services run in Session 0. The service still exposes the WebUI on the configured localhost address.

## Build on Windows

Requirements:

- Windows 10/11 x64
- Go with toolchain switching support; release builds force the exact `go1.26.8` toolchain
- Node.js `22.17.0` for release-candidate WebUI checks
- the exact official WinDivert `2.2.2` x64 runtime

Get the runtime files from the official WinDivert 2.2.2 release page:

- https://github.com/basil00/WinDivert/releases/tag/v2.2.2

For a normal local build, place these files in the repository root. Their
official SHA-256 digests are verified before they are copied next to the built
executable:

- `WinDivert.dll`
- `WinDivert64.sys`

Build through the command wrapper. It invokes `build.ps1` with the Windows
PowerShell execution-policy bypass and forwards all arguments:

```cmd
build.cmd
```

Or invoke the same script directly:

```powershell
.\build.ps1 -Version dev
```

Both entry points force `windows/amd64`, `GOAMD64=v1`, `CGO_ENABLED=0`,
`-mod=readonly`, `-trimpath`, Go `1.26.8`, and `GOWORK=off`. Release builds also
ignore per-user Go environment files and reject unexpected experiment/FIPS
modes. Go may download the pinned toolchain on the first build. A missing
WinDivert runtime produces a development-build warning; an existing runtime in
either the source or output directory is accepted only when its exact hash
matches.

To prepare a reviewable release candidate, first commit all intended source
changes, then run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\package-release.ps1 -Version v0.44 -DownloadWinDivertArchive
```

The candidate is written to `build\candidates\v0.44\`; it does not replace
`build\pitchProx.exe` or interact with a running pitchProx process. The release
script runs all Go and WebUI checks, then obtains and verifies the pinned
official WinDivert archive for a release-grade updater manifest. If a network
filter blocks GitHub downloads, the mutually exclusive
`-WinDivertArchivePath C:\path\WinDivert-2.2.2-A.zip` option accepts an existing
copy only after the same pinned SHA-256 and internal runtime/license checks.
Temporary extraction remains inside the candidate tree and is removed before packaging;
the running application and root runtime files are untouched. The script also
includes third-party licenses and writes a build manifest plus SHA-256 file. It
refuses recursive cleanup through junctions/symlinks.
`-AllowDirty` is only for disposable test builds; `-SkipChecks` is accepted
only together with it. A publishable candidate must report a clean tree,
completed checks, the injected version, and `vcs.modified=false`.

The `cmd/pitchprox/pitchprox_windows_amd64.syso` resource file is already checked into the repo, so the pitchProx route icon is embedded by a normal Go build on Windows.

## First run

Run from an elevated PowerShell/Terminal, or just double-click `pitchProx.exe` and approve the UAC prompt.

```powershell
build\pitchProx.exe
```

Default WebUI address:

```text
http://127.0.0.1:18080
```

The WebUI opens on the Rules page and provides:

- sidebar navigation for Monitoring, Rules, Proxies, Chains, Dropped connections, and the event log;
- local rule search across names, comments, every application/host/port value, actions, proxies, and chains;
- filters, pagination, one consistently compact table, configurable columns, and atomic bulk operations;
- clipboard-first versioned rules-only import/export with JSON textareas,
  retained file load/download actions, bounded preview, and no proxy credentials;
- demand-only bounded per-rule activity charts;
- lazy Application + Host + Port condition coverage without expanding a rule
  into a potentially huge Cartesian product; details are coalesced into bounded
  15-second aggregates so snapshot frequency does not amplify disk writes.

One rule may still contain multiple Applications, Target hosts, and Target ports. These values remain raw strings in the config and keep the syntax documented below.

## Config file

For headless agents, use `pitchProx.exe ctl help` and `pitchProx.exe ctl schema`.
The CLI can read, validate, preview and apply settings and individual rules even
while the WebUI is disabled. See [Agent CLI](docs/AGENT_CLI.md) for revision-safe
writes, connection-preserving reloads, HTTP listener handoff and examples.

pitchProx stores its config next to the executable:

```text
pitchProx.config.json
```

This is deliberate so a prepared setup can be copied to another machine together with the executable.

The runtime history store is also portable and lives next to the executable:

```text
pitchProx.history\
```

## Rule syntax summary

### Applications

Supported examples:

```text
*
firefox.exe
fire*.exe
"*.bin"
"C:\Program Files\JetBrains\*"
12345
chrome.exe; brave.exe
firefox.exe,
msedge.exe
```

Notes:

- `*` or `Any` means any process.
- Plain number means **PID**.
- No backslash: match against executable file name.
- Contains a drive letter or backslash: match against full executable path.
- `*` and `?` work as wildcards.
- `;`, comma, and newline are all valid separators.
- Quotes preserve tokens with spaces or commas.

### Target hosts

Supported examples:

```text
Any
localhost; 127.0.0.1; ::1; %ComputerName%
*.example.com
192.168.1.*
10.1.0.0-10.5.255.255
192.168.0.0/16
github.com,
download.jetbrains.com
```

### Target ports

Supported examples:

```text
Any
80
443; 3128
8000-9000
```

## WebUI summary

Main areas:

- **Rules** - ordered ruleset, quick enable/disable, move up/down, edit dialog.
- **Proxies** - proxy profiles with inline target and test button.
- **Chains** - ordered lists of proxy IDs.
- **Proxy activity** - proxied Rx/Tx graph and totals for the configured retention window.
- **Active connections** - grouped connection table with a free-text search field plus rule/action click-filters.
- **Log** - live event log with process/rule/action filtering.

### Application updates

The Settings dialog checks GitHub Releases only after **Проверить обновления**
is pressed. It reports whether a newer stable version exists and always shows
up to five latest published releases. Any compatible listed version can be
installed, including an explicitly confirmed downgrade.

Installation downloads and verifies the selected executable beside the running
application, then hands a bounded transaction to a short-lived helper. The
helper stops the exact current process/service, atomically replaces the
executable, starts the selected build, and removes the old executable only
after three successful health checks. If the new build does not start, the
verified old executable is restored and restarted. Configuration, history, and
the installed WinDivert runtime are not replaced.

Current release-format builds require matching GitHub asset digests, the
published SHA-256 file, and a clean build manifest compatible with the local
WinDivert DLL/driver. Older pre-manifest releases are offered only when their
complete ZIP proves that their WinDivert runtime exactly matches the installed
one. After downgrading to such a legacy build, the updater is no longer present;
return to a current build manually if needed.

## Documentation map

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - runtime architecture and data flow.
- [docs/RULE_LANGUAGE.md](docs/RULE_LANGUAGE.md) - full rule syntax and matching semantics.
- [docs/UI_REFERENCE.md](docs/UI_REFERENCE.md) - WebUI layout and user workflows.
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md) - localhost HTTP API used by the WebUI.
- [docs/RECREATION_SPEC.md](docs/RECREATION_SPEC.md) - text-only specification detailed enough to recreate the program from scratch.
- [docs/CODE_MAP.md](docs/CODE_MAP.md) - source file map by responsibility.
- [docs/CODE_AUDIT_2026-07-28.md](docs/CODE_AUDIT_2026-07-28.md) - code audit, long-running resource fixes, decisions, and remaining isolated tests.
- [docs/HISTORICAL_CPU_DIAGNOSTICS_2026-04-15.md](docs/HISTORICAL_CPU_DIAGNOSTICS_2026-04-15.md) - preserved CPU investigation that motivated later runtime optimizations.
- [docs/GITHUB_SETUP.md](docs/GITHUB_SETUP.md) - how to publish the repository to GitHub and use the included CI and release workflow.
- [docs/RELEASE_NOTES_v0.44.md](docs/RELEASE_NOTES_v0.44.md) - release notes used for the v0.44 GitHub Release body.
- [CHECKS.md](CHECKS.md) - verification notes for this archive.
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) - bundled dependency notices and license locations.

## GitHub Actions CI

This archive includes a ready-to-commit workflow at:

```text
.github/workflows/ci.yml
```

It invokes the same release script as a local candidate: pinned Go and Node.js
versions, WebUI checks, Go tests and `go vet`, exact Windows amd64/CGO-disabled
build settings, verified WinDivert inputs, licenses, deterministic ZIP entry
ordering/timestamps, a build manifest, and SHA-256 checksums.

The CI invocation explicitly downloads the official WinDivert 2.2.2 archive
and accepts it only when the pinned archive, DLL, driver, and license SHA-256
values all match. Local candidates instead reuse the already present verified
root runtime. The complete tracked WinDivert license and third-party notices
are included in either ZIP, and the manifest records which runtime source was
used.

A push to any branch, a pull request, or a manual workflow run executes the
Windows build and uploads packaged workflow artifacts.

If you push an approved tag such as `v0.44`, the same workflow also creates a
versioned GitHub Release automatically. A matching
`docs/RELEASE_NOTES_v<major>.<minor>.md` file is required, so future tags cannot
silently reuse notes from v0.43. The release attaches:

- `pitchProx.exe`
- `pitchProx-windows-amd64.zip`
- `pitchProx-windows-amd64.sha256`
- `pitchProx-build-manifest.json`

## Performance model

Desktop mode is optimized for a quiet idle state:

- the tray reads a lightweight in-process traffic view instead of the full WebUI snapshot;
- verbose `info/debug` logging is captured only while the WebUI is open or recently active;
- connection/log/rule/traffic history is stored in compact hourly file segments instead of remaining in RAM;
- when the WebUI tab is hidden or closed, the backend is explicitly allowed to cool back down instead of treating the UI as permanently active;
- after one hour without a marked browser request, only WebUI is automatically paused; one lazy deadline timer is used, proxy routing continues unchanged, and the tray exposes **Включить WebUI** while **Управление** remains an enable-and-open shortcut;
- GitHub release discovery is strictly on demand; outside an active check or installation the updater performs no network polling and retains only a bounded five-release cache;
- WebUI traffic snapshots are server-bucketed to a bounded series, so long retention windows do not materialize huge per-second payloads in the backend or browser;
- if every enabled rule is `Direct`, pitchProx starts in observer-only mode and does not start WinDivert or the transparent listener at all;
- otherwise a lightweight SYN classifier decides whether a connection needs interception; a shared redirector is opened lazily while at least one selected flow exists and is closed again as soon as the flow table becomes empty;
- direct-bypass TCP observation now becomes truly dormant when no active UI client is present, instead of continuing periodic full TCP-table scans in the background; its WebUI-only PID/path snapshot cache is released on dormancy;
- owner-PID resolution is refreshed on demand instead of by a hot periodic full-table scan, and cached executable identity is validated with both PID and process creation time;
- history uses event-driven, batched JSONL writes without SQLite/WAL or an idle polling ticker; incomplete crash tails are truncated and isolated malformed lines are skipped;
- failed history writes retry at a reduced rate and all emergency in-memory queues are bounded, so a full or unavailable disk cannot make RAM grow indefinitely;
- large connection maps geometrically release retained high-water capacity as bursts drain, even when one connection stays open, and the lazy WinDivert cleanup timer sleeps while there are no intercepted flows;
- forced heap release runs only when there is a meaningful amount of reclaimable memory, avoiding periodic GC work in an already-small idle heap;
- the WebUI snapshot interval is 15 seconds and the configured HTTP listener is restricted to IPv4/IPv6 loopback addresses.

## Historical performance note

A preserved CPU diagnostic from 2026-04-15 is included in `docs/HISTORICAL_CPU_DIAGNOSTICS_2026-04-15.md`.
It is kept as a historical design record because it identified the original kernel-heavy interception tax on `Direct` traffic. The exact numbers are historical, but the architectural lesson remains important.

## Known limitations

- TCP only.
- Existing connections created before pitchProx starts are not retroactively adopted.
- Hostname recovery is strongest for HTTP and TLS because those protocols expose `Host` or `SNI`.
- UDP/QUIC/HTTP3 are out of scope in the current codebase.
- Service mode is headless; the tray belongs to desktop mode.

## Windows build notes

The main release build is produced as a **GUI subsystem** executable. This avoids a separate `conhost.exe` when `pitchProx.exe` is launched by double click from Explorer.

Use:

```powershell
.\build.ps1 -Version dev
```

If you build manually and want the same behavior, use:

```powershell
$env:GOTOOLCHAIN = 'go1.26.8'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:GOAMD64 = 'v1'
$env:CGO_ENABLED = '0'
$env:GOWORK = 'off'
$env:GOENV = 'off'
$env:GOEXPERIMENT = ''
$env:GOFIPS140 = 'off'
go build -mod=readonly -trimpath -buildvcs=true -ldflags="-H=windowsgui -s -w -X github.com/agentpitch/prox/internal/buildinfo.Version=dev" -o build\pitchProx.exe .\cmd\pitchprox
```

The release script additionally produces a ZIP with ordinally sorted entries and a fixed
source-commit timestamp. Reproducibility here means pinned source, toolchain,
target, dependencies, and packaging inputs; it is not a formal promise that
independent Windows/.NET environments will always emit byte-identical files.

Tracked text uses repository-defined line endings so embedded WebUI bytes do
not depend on a contributor's Git `core.autocrlf` setting.

pitchProx itself currently has no declared open-source license. The bundled
license files cover third-party components only; choose and add a project
license before publishing if redistribution rights are intended.

Release executables are currently unsigned. Windows may show a SmartScreen
warning even though the bundled WinDivert 2.2.2 driver/runtime files are the
official upstream binaries verified by SHA-256.

The Windows executable/tray icon and the WebUI favicon are generated together from `assets/pp_icon_256.png`; the Windows resource object is `cmd/pitchprox/pitchprox_windows_amd64.syso`. With Pillow available, regenerate all derived icon files with:

```powershell
python .\tools\make_icon_syso.py
```

WebUI also serves the embedded application icon at `/favicon.ico` and `/pp_icon_256.png`.
