# GitHub repository and CI setup

This repository is prepared for GitHub Actions and automatic GitHub Releases.

## Included workflow

- `.github/workflows/ci.yml`

It builds `pitchProx.exe` on `windows-latest`, using the Go version declared in
`go.mod`, downloads the WinDivert runtime from the official `v2.2.2` release,
packages a Windows zip and checksum file, uploads them as workflow artifacts,
publishes a prerelease automatically on each push to `main`, and publishes a
versioned GitHub Release automatically when you push a tag that matches `v*`.

Triggers:

- `push`
- `pull_request`
- `workflow_dispatch`
- tag push `v*`

## Recommended first-time setup

1. Create a new empty repository on GitHub, for example `pitchprox`.
2. Push this project into that repository.
3. Open the **Actions** tab once to allow workflows if GitHub prompts you.
4. Push a commit or run the workflow manually with **Run workflow** to confirm the Windows build passes.
5. Push to `main` to publish a prerelease automatically for that commit.
6. Download the generated artifact from the workflow run if you want to inspect the packaged output.
7. Create and push a version tag to publish a versioned release automatically:

```powershell
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

8. Open the **Releases** page and verify that GitHub published the new prerelease or release with the generated assets.

## What the release contains

- `pitchProx.exe`
- `pitchProx-windows-amd64.zip`
- `pitchProx-windows-amd64.sha256`

Main branch pushes publish these assets as prereleases tagged `main-<sha>`.
Version tags `v*` publish the same assets as normal GitHub Releases.

## Optional follow-ups

- Add branch protection so `main` requires the Windows build to pass.
- If you need a reproducible corporate environment, move the build to a self-hosted Windows runner.
- If you want manual release notes instead of generated ones, edit `.github/workflows/ci.yml`.

## Notes about WinDivert

The workflow downloads `WinDivert.dll` and `WinDivert64.sys` automatically from:

- https://github.com/basil00/WinDivert/releases/tag/v2.2.2

This keeps the packaged GitHub Release self-contained even if those files are not committed to the repository.
