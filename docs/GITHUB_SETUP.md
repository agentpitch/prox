# GitHub repository and CI setup

This repository is prepared for GitHub Actions and automatic GitHub Releases.

## Included workflow

- `.github/workflows/ci.yml`

It builds `pitchProx.exe` on `windows-latest`, using the Go version declared in
`go.mod`, packages a Windows zip and checksum file, uploads them as workflow
artifacts, and publishes a GitHub Release automatically when you push a tag that
matches `v*`.

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
5. Download the generated artifact from the workflow run if you want to inspect the packaged output.
6. Create and push a version tag to publish a release automatically:

```powershell
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

7. Open the **Releases** page and verify that GitHub published the new release with the generated assets.

## What the release contains

- `pitchProx.exe`
- `pitchProx-windows-amd64.zip`
- `pitchProx-windows-amd64.sha256`

## Optional follow-ups

- Add branch protection so `main` requires the Windows build to pass.
- If you need a reproducible corporate environment, move the build to a self-hosted Windows runner.
- If you want manual release notes instead of generated ones, edit `.github/workflows/ci.yml`.

## Notes about WinDivert

The workflow builds the executable. If your repository also stores `WinDivert.dll`
and `WinDivert64.sys`, the workflow copies them into the packaged zip automatically.
If those files are absent, the workflow still succeeds and publishes the built exe,
zip, and checksum anyway.
