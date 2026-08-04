# pitchProx v0.43

## Highlights

- New application-shell WebUI with sidebar navigation and dedicated pages.
- Dense rules table with search by name, ID, comment, every application, host, port, action, proxy, and chain.
- Rule priority is shown once in the order column without a duplicate `#number` prefix in the name.
- The rules search keeps one explicit clear button instead of also exposing the browser-native search clear control.
- Filters, 25/50 pagination, one consistently compact table, persistent column preferences, and responsive mobile layout.
- Multi-selection and atomic bulk enable, disable, and delete.
- Multiline rule comments using the existing compatible `notes` field.
- Redesigned editor that preserves raw multi-app, multi-host, and multi-port syntax.
- New route-style Windows, tray, and WebUI application icon.
- Syntax warnings, stable-ID validation, dirty-editor protection, and advisory similar-rule detection.
- Versioned rules-only import/export without proxy credentials.
- Real demand-only rule activity sparklines with strict ID, window, and point bounds.
- Lazy bounded per-rule breakdown of observed Application + Host + Port tuples,
  including marginal coverage for identifying alternatives with no observed use.
- Condition details are coalesced into one tuple/source record per 15-second
  bucket with a 256-key admission budget, bounding disk and scan work even for
  pathological rule cardinality or frequent WebUI snapshots.
- Live SSE/snapshot work now runs only on Monitoring and Journal pages.
- WebUI automatically pauses after one hour without marked browser requests,
  while proxy routing continues; tray/control endpoints remain available to
  enable it again. The deadline uses one lazy timer with no idle polling.
- Build version is reported by the API and injected into release binaries.
- Long-running resource hardening from the post-v0.41 work is included: bounded history recovery/retries, PID creation-time validation, released high-water buffers, stricter protocol parsing, and transactional runtime-config activation.
- WebUI-only process metadata is released on dormancy, and connection maps compact geometrically after traffic bursts even when a long-lived connection remains.

## Release integrity

- Windows target is fixed to `amd64`, `GOAMD64=v1`, `CGO_ENABLED=0`, and Go `1.26.5`.
- Source builds use read-only module mode and must report the intended commit with `vcs.modified=false`.
- The WinDivert 2.2.2 DLL, driver, tracked verbatim license, and official CI archive are pinned by SHA-256; local packaging reuses the verified root runtime without duplicate extraction.
- The full ZIP includes WinDivert, Go, and `golang.org/x/sys` licenses and third-party notices.
- `pitchProx-build-manifest.json` records the source commit, toolchain, target, dependency hashes, and executable hash.
- `pitchProx-windows-amd64.sha256` covers the standalone executable, ZIP, and manifest and is verified before a tag release is published.

## Compatibility

- No configuration migration is required.
- `config.version` remains `1`.
- Existing rule strings and comments remain compatible.
- History stays in the existing bounded JSONL store; no SQLite dependency was added.
- WinDivert remains version `2.2.2`.

## Installation note

The complete ZIP is the recommended download for a new installation. The
standalone executable is intended for updating an existing directory that
already contains the verified WinDivert runtime. `pitchProx.exe` itself is not
code-signed, so Windows SmartScreen may show a warning; the included WinDivert
runtime is the unchanged official upstream build verified by SHA-256.
