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

- `Direct` — connect directly to the original destination.
- `Proxy` — connect through one proxy profile.
- `Chain` — connect through a sequence of proxy profiles.
- `Block` — deny the connection.

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
- Go 1.25+
- WinDivert 2.2.2+

Place these files next to the built executable:

- `WinDivert.dll`
- `WinDivert64.sys`

Build:

Without PowerShell scripts (recommended if execution policy blocks `build.ps1`):

```cmd
build.cmd
```

Or manually from PowerShell:

```powershell
go mod tidy
New-Item -ItemType Directory -Force -Path build | Out-Null
go build -trimpath -ldflags="-H=windowsgui -s -w" -o build\pitchProx.exe .\cmd\pitchprox
```

The `cmd/pitchprox/pitchprox_windows_amd64.syso` resource file is already checked into the repo, so the `pp` icon is embedded by a normal `go build` on Windows.

If you want to use the optional PowerShell wrapper instead, first allow the script under your local PowerShell execution policy and then run:

```powershell
.\build.ps1
```

## First run

Run from an elevated PowerShell/Terminal, or just double-click `pitchProx.exe` and approve the UAC prompt.

```powershell
build\pitchProx.exe
```

Default WebUI address:

```text
http://127.0.0.1:18080
```

## Config file

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

- **Rules** — ordered ruleset, quick enable/disable, move up/down, edit dialog.
- **Proxies** — proxy profiles with inline target and test button.
- **Chains** — ordered lists of proxy IDs.
- **Proxy activity** — proxied Rx/Tx graph and totals for the configured retention window.
- **Active connections** — grouped connection table with a free-text search field plus rule/action click-filters.
- **Log** — live event log with process/rule/action filtering.

## Documentation map

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — runtime architecture and data flow.
- [docs/RULE_LANGUAGE.md](docs/RULE_LANGUAGE.md) — full rule syntax and matching semantics.
- [docs/UI_REFERENCE.md](docs/UI_REFERENCE.md) — WebUI layout and user workflows.
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md) — localhost HTTP API used by the WebUI.
- [docs/RECREATION_SPEC.md](docs/RECREATION_SPEC.md) — text-only specification detailed enough to recreate the program from scratch.
- [docs/CODE_MAP.md](docs/CODE_MAP.md) — source file map by responsibility.
- [docs/HISTORICAL_CPU_DIAGNOSTICS_2026-04-15.md](docs/HISTORICAL_CPU_DIAGNOSTICS_2026-04-15.md) — preserved CPU investigation that motivated later runtime optimizations.
- [docs/GITHUB_SETUP.md](docs/GITHUB_SETUP.md) — how to publish the repository to GitHub and use the included CI workflow.
- [CHECKS.md](CHECKS.md) — verification notes for this archive.



## GitHub Actions CI

This archive includes a ready-to-commit workflow at:

```text
.github/workflows/windows-build.yml
```

It builds `pitchProx.exe` on a GitHub-hosted Windows runner and uploads the result as a workflow artifact.

## Performance model

Desktop mode is optimized for a quiet idle state:

- the tray reads a lightweight in-process traffic view instead of the full WebUI snapshot;
- verbose `info/debug` logging is captured only while the WebUI is open or recently active;
- connection/log/rule/traffic history is stored in compact hourly file segments instead of remaining in RAM;
- if every enabled rule is `Direct`, pitchProx starts in observer-only mode and does not start WinDivert or the transparent listener at all;
- otherwise a lightweight SYN classifier decides whether a connection needs interception, and only those flows get dedicated WinDivert packet handling;
- owner-PID resolution is refreshed on demand instead of by a hot periodic full-table scan.



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
.\build.ps1
```

If you build manually and want the same behavior, use:

```powershell
go build -trimpath -ldflags="-H=windowsgui -s -w" -o build\pitchProx.exe .\cmd\pitchprox
```

The file icon is embedded from `assets/pp_icon_256.png` through the generated resource object `cmd/pitchprox/pitchprox_windows_amd64.syso`. To regenerate it, run:

```powershell
python .\tools\make_icon_syso.py
```


WebUI also serves the embedded application icon at `/favicon.ico` and `/pp_icon_256.png`.
