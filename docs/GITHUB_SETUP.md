# GitHub repository and release setup

See [GITHUB.md](GITHUB.md) for the exact CI inputs, artifact contents, and tag
publication behavior.

## Initial repository setup

1. Push the complete source history to the intended GitHub repository.
2. Enable GitHub Actions if the repository settings require it.
3. Push a normal branch commit or run `workflow_dispatch`.
4. Confirm that the `windows-build` job succeeds and download its artifact.
5. Verify `pitchProx-windows-amd64.sha256` and inspect
   `pitchProx-build-manifest.json` before enabling a release tag workflow.
6. Decide and add a first-party `LICENSE` if open-source redistribution is intended; dependency licenses do not cover pitchProx itself.
7. Protect `main` so the Windows CI job is required before merge.

The workflow requires only the built-in `GITHUB_TOKEN`. The tag publication job
elevates its permission to `contents: write`; normal builds remain read-only.

## Local candidate before a tag

From a committed clean working tree on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\package-release.ps1 -Version v0.43 -DownloadWinDivertArchive
```

Review the files under `build\candidates\v0.43\`. This path is separate
from `build\pitchProx.exe`, so packaging does not overwrite or stop an already
running main application. `-DownloadWinDivertArchive` verifies the pinned
official archive and produces the release-grade manifest required by the
built-in updater; it does not load the driver or touch a running application.
When direct download is unavailable, use
`-WinDivertArchivePath C:\path\WinDivert-2.2.2-A.zip` instead; the options are
mutually exclusive and the local archive must pass the identical pinned hash
and content checks.
Without either archive option the local script may reuse the verified root runtime, but
the resulting manifest is intended only for local review and must not be
published as an updater-compatible release.

`-AllowDirty` is a diagnostic convenience only, and `-SkipChecks` is accepted
only together with it. Artifacts made with either switch are not release
approvals.

## Publish an approved version

Push exactly one intended tag:

```powershell
git tag -a v0.43 -m "v0.43"
git push origin v0.43
```

Never substitute `git push --tags` unless every local tag has been deliberately
audited. Every pushed `v*` tag starts an automatic GitHub Release.
Before tagging a new major/minor line, add its matching curated notes file (for
example, `docs/RELEASE_NOTES_v0.44.md`); packaging intentionally fails rather
than reusing notes from another release line.

The release contains:

- `pitchProx.exe`;
- `pitchProx-windows-amd64.zip`;
- `pitchProx-windows-amd64.sha256`;
- `pitchProx-build-manifest.json`.

The ZIP is the complete new-install package. It contains the verified official
WinDivert 2.2.2 x64 runtime, upstream WinDivert license, Go and
`golang.org/x/sys` licenses, `THIRD_PARTY_NOTICES.md`, README, checks, and docs.

The built-in updater depends on the four asset names above being unique and
unchanged. Current releases must include the manifest; deleting, renaming, or
re-uploading one asset makes that release unavailable for automatic install.

## Signing and runtime tests

The pitchProx executable is currently unsigned and may trigger SmartScreen. CI
does not start the executable, install a service, display the tray, or load the
WinDivert driver. Perform those checks separately on a VM or during an approved
test window where the production instance is not competing for the same driver,
ports, or configuration.
