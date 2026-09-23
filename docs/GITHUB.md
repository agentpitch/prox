# GitHub CI and releases

The repository uses `.github/workflows/ci.yml` for Windows validation,
packaging, and tag-based GitHub Releases.

## Single release path

Both local candidates and GitHub Actions execute
`tools/package-release.ps1`. The local default reuses the verified
`WinDivert.dll` and `WinDivert64.sys` already in the repository root; CI passes
the explicit `-DownloadWinDivertArchive` switch because ignored runtime
binaries are not present in a fresh checkout. The workflow does not maintain a
second copy of the build/package commands or hashes.

A candidate intended to exercise or publish the built-in updater must use
`-DownloadWinDivertArchive`, or `-WinDivertArchivePath` with an existing exact
copy when direct download is unavailable. Both paths verify the pinned archive,
its DLL, driver, and license before recording `verified-official-archive` and
the archive digest in the manifest. A manifest made from repository-root runtime
files remains useful for local inspection, but the updater deliberately rejects
it as a published supply-chain input.

The release path fixes:

- Go `1.26.5`;
- Node.js `22.17.0` for WebUI checks;
- `windows/amd64`, `GOAMD64=v1`, and `CGO_ENABLED=0`;
- read-only Go module mode, `GOWORK=off`, `GOENV=off`, default experiment/FIPS modes, and `-trimpath`;
- the official WinDivert 2.2.2 archive, DLL, driver, and license SHA-256 values.

Every native command is checked before the next command runs. A clean candidate
must run the full gate and retain a clean Git tree. It verifies module-cache
content, the exact repository `go.mod`, and both working-tree and committed
whitespace. The script statically checks
the exact injected version; executable metadata must report the intended commit
with `vcs.modified=false`.

## Workflow output

The Windows job runs WebUI syntax/unit checks, Go tests, `go vet`, builds the GUI
subsystem executable, verifies WinDivert, and creates:

- `pitchProx.exe` — standalone update executable;
- `pitchProx-windows-amd64.zip` — complete package with WinDivert and licenses;
- `pitchProx-windows-amd64.sha256` — hashes for the executable, ZIP, and manifest;
- `pitchProx-build-manifest.json` — commit/toolchain/target/input metadata;
- `RELEASE_NOTES.md` — release body source.

The ZIP uses ordinally sorted entries and the source commit timestamp. This removes common
ordering/time variance, while the project defines reproducibility primarily as
pinned source, toolchain, target, modules, and third-party inputs rather than a
formal cross-Windows byte-for-byte guarantee.

`.gitattributes` fixes tracked source/document text to LF (with CRLF only for
batch wrappers), so `go:embed` inputs do not vary with `core.autocrlf`. Candidate
cleanup rejects reparse points in the output parent chain and candidate tree.
Third-party actions in the workflow are pinned to full commit SHAs.

## Triggers

- a push to any branch;
- a pull request;
- manual `workflow_dispatch`;
- a tag matching `v*`.

Branch builds use `dev-<short-commit>` as their embedded version. Tag builds use
the exact tag. The packaging script rejects malformed version tags even though
the workflow trigger itself uses the broader `v*` pattern. For a tag such as
`v0.44` or `v0.44-rc.1`, the script requires
`docs/RELEASE_NOTES_v0.44.md`; future major/minor tags therefore cannot
silently publish v0.44 notes. Development artifacts receive a neutral generated
note instead.

## Publishing

After reviewing a clean candidate and merging the approved commit to `main`,
create and push only the intended annotated tag:

```powershell
git tag -a v0.44 -m "v0.44"
git push origin v0.44
```

Do not use `git push --tags` as a release command: unrelated local tags would
also trigger releases. A tag immediately starts the publication workflow, so it
must not be created or pushed before approval.

The release job downloads the Windows artifact, verifies its SHA-256 file on
Linux, then publishes the executable, ZIP, checksum, and manifest. The curated
v0.44 notes are prepended to GitHub-generated change notes. Tags containing a
hyphen, such as `v0.44-rc.1`, are marked as prereleases.

The built-in updater treats these exact unique asset names as an API contract.
It cross-checks the GitHub asset SHA-256 digest, checksum file, executable, and
manifest before staging an update. Therefore a published asset must never be
renamed or replaced in place; publish a new version instead. Releases from
`v0.42` onward are installable only with a valid manifest. Older releases use a
restricted compatibility path that also verifies the ZIP's WinDivert runtime
against the currently installed DLL and driver.

## Runtime scope

GitHub-hosted CI does not execute the built application or load the WinDivert
driver. Elevated networking, tray, and Windows Service behavior require a
separate controlled test window or VM.

Release executables are currently unsigned. SmartScreen may warn about
`pitchProx.exe`; the WinDivert runtime inside the ZIP is the official upstream
2.2.2 build verified by hash and accompanied by its license.

The repository currently has no first-party `LICENSE`. Dependency license files
do not grant rights to pitchProx itself; the owner must choose a project license
before publication if open-source redistribution is intended.
