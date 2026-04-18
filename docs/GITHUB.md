# GitHub setup

This repository includes a minimal GitHub Actions CI workflow for Windows builds.

## Files

- `.github/workflows/ci.yml` — build and test on `push`, `pull_request`, and `workflow_dispatch`
- `build.cmd` — local Windows build helper

## What CI does

1. checks out the repository;
2. sets up Go from `go.mod`;
3. runs `go test ./...`;
4. builds `build/pitchProx.exe` with the Windows GUI subsystem;
5. uploads the `build/` directory as a workflow artifact.

## Notes

- The workflow builds on `windows-latest` because pitchProx is Windows-only.
- Runtime integration with WinDivert is **not** exercised in GitHub-hosted CI. The CI pipeline is a
  build-and-basic-test pipeline, not a full driver/runtime integration test.
- The repository currently does not need `go.sum` to exist ahead of time. `actions/setup-go` can use
  module caching keyed from `go.mod`.
