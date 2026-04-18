# GitHub repository and CI setup

This repository is prepared for GitHub Actions.

## Included workflow

- `.github/workflows/windows-build.yml`

It builds `pitchProx.exe` on `windows-latest`, using the Go version declared in
`go.mod`, and uploads the resulting executable and a zip archive as workflow
artifacts.

Triggers:

- `push`
- `pull_request`
- `workflow_dispatch`

## Recommended first-time setup

1. Create a new empty repository on GitHub, for example `pitchprox`.
2. Push this project into that repository.
3. Open the **Actions** tab once to allow workflows if GitHub prompts you.
4. Run the workflow manually with **Run workflow** or push a commit.
5. Download the generated artifact from the workflow run.

## Optional follow-ups

- Add a tag-based release workflow if you want GitHub Releases to contain the built
  Windows zip.
- Add branch protection so `main` requires the Windows build to pass.
- If you need a reproducible corporate environment, move the build to a self-hosted
  Windows runner.

## Notes about WinDivert

The workflow builds the executable. If your repository also stores `WinDivert.dll`
and `WinDivert64.sys`, the workflow copies them into the packaged zip automatically.
If those files are absent, the workflow still succeeds and uploads the built exe.
