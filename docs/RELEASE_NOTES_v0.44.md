# pitchProx v0.44

## Background efficiency and reliability

- Build with Go 1.26.8, including standard-library security fixes released
  after the previous Go 1.26.5 pin.
- Reduce temporary allocations while detecting HTTP hostnames and matching rules.
- Avoid frequent full map rebuilds while many connections remain active; release
  high-water capacity after traffic bursts.
- Release sniff/CONNECT prefix buffers after use instead of retaining them for
  the lifetime of a tunnel. Bound upstream CONNECT response headers to 64 KiB.
- Close sockets that race with shutdown and cancel pending proxy handshakes.
- Compact dropped-connection history with free space for subsequent writes,
  keeping its configured hard size limit.
- Skip SSE serialization without subscribers, promptly remove disconnected
  subscribers, and stop hidden Settings updater polling.
- Create tray icons in memory, correctly release native resources, and avoid
  repeated forced memory trimming merely because live heap usage is high.

The resource audit includes repeatable microbenchmarks and their limits in
`docs/RESOURCE_AUDIT_2026-09-23.md`. These results are not a guarantee of a fixed
percentage reduction in whole-application CPU or RAM usage.

## Headless control for CLI agents

- `pitchProx.exe ctl schema` describes the commands, JSON inputs, output and
  errors without a running server. `ctl help` provides a human-readable guide.
- Read configuration and rules, validate locally, preview changes, and apply
  them while WebUI is disabled or idle-paused.
- Edit, insert, move and delete rules by stable ID. Revision checks prevent
  stale agent or WebUI writes from overwriting newer configuration.
- Ordinary rule/proxy changes apply to new connections while established
  connections keep their route. No-op applies do not rewrite the file.
- HTTP address changes pre-bind the replacement listener, return the response
  through the old listener and retain the same process. Changes that restart
  interception require explicit `--allow-disruptive` for CLI clients.
- JSON output, bounded UTF-8 input, stable exit codes and no automatic retries
  after an unconfirmed write support predictable automation.

See `docs/AGENT_CLI.md` for the full workflow and PowerShell UTF-8 examples.
Directly editing the live configuration file does not trigger a reload; use
the CLI/API to persist and activate changes together. `ctl` does not install
a background agent or poll configuration files.

## Tray

Double-clicking the tray icon opens **Monitoring → All**, clearing the previous
connection search and process/rule focus. Subsequent choices within the WebUI
remain under user control.

## Compatibility and installation

- Configuration format remains version 1 and history stays in the existing
  JSONL format. Existing files without `updated_at` acquire a persisted revision
  on startup; no manual migration is required.
- The local HTTP port must now be numeric and in 1..65535. Ephemeral port 0 and
  named service ports are rejected so CLI discovery can find the saved address.
- CLI commands that contact the running instance require v0.44 or newer. Upgrading the EXE
  requires one normal application restart; later ordinary rule edits do not.
- WinDivert remains the SHA-256-verified official 2.2.2 runtime. The complete ZIP
  includes its DLL, driver and license, plus Go/x/sys licenses and documentation.
- For a new installation, download the complete ZIP. The standalone EXE is for
  an existing installation with the matching WinDivert files. Keep the existing
  configuration and history when updating.
- The executable is not code-signed; Windows SmartScreen may show a warning.

## Verification

Release packaging requires a clean committed source tree, Go 1.26.8,
Node.js 22.17.0, Go tests/vet, JavaScript checks and tests, exact runtime hashes,
clean VCS metadata, a build manifest and verified SHA-256 checksums.
GitHub CI also checks for reachable known Go vulnerabilities with pinned
`govulncheck` v1.8.0 before packaging.
Windows race-detector tests and isolated GUI-subsystem executable/CLI checks
also passed during preparation, including revision conflicts, rollback,
runtime restart and listener handoff with unchanged PID.

Live elevated WinDivert interception, installed Windows Service update/rollback
and a multi-day traffic soak were not exercised for this release. The isolated
runtime checks use Direct rules and do not disturb an existing installation.
