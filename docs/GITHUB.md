# GitHub setup

This repository includes a single GitHub Actions workflow for Windows CI and tag-based releases.

## Files

- `.github/workflows/ci.yml` - build, package, and release on GitHub Actions
- `build.cmd` - local Windows build helper

## What the workflow does

1. checks out the repository;
2. sets up Go from `go.mod`;
3. downloads Go modules;
4. runs `go test ./...`;
5. builds `build/pitchProx.exe` with the Windows GUI subsystem;
6. packages `pitchProx.exe`, optional WinDivert runtime files, `README.md`, `CHECKS.md`, and `docs/` into `pitchProx-windows-amd64.zip`;
7. generates `pitchProx-windows-amd64.sha256`;
8. uploads the packaged release files as a workflow artifact.

When the ref is a tag starting with `v`, the workflow also:

9. creates a GitHub Release automatically;
10. attaches the executable, zip archive, and checksum file to that release;
11. lets GitHub generate release notes from merged changes.

## Triggers

- `push` on any branch
- `pull_request`
- `workflow_dispatch`
- `push` of a tag matching `v*`

## Release usage

Create and push an annotated tag such as:

```powershell
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

That tag starts the same workflow and publishes the release automatically.

## Notes

- The build job runs on `windows-latest` because pitchProx is Windows-only.
- The release job uses the built-in `GITHUB_TOKEN`; no extra secret is required for standard releases in the same repository.
- Runtime integration with WinDivert is **not** exercised in GitHub-hosted CI. The workflow is a build-and-basic-test pipeline, not a full driver/runtime integration test.
