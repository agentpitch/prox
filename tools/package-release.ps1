param(
    [string]$Version = "v0.44.1",
    [switch]$SkipChecks,
    [switch]$AllowDirty,
    [switch]$DownloadWinDivertArchive,
    [string]$WinDivertArchivePath = "",
    [string]$ReleaseNotesSource = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "release-common.ps1")

function New-PitchProxDeterministicZip {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDirectory,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        [Parameter(Mandatory = $true)]
        [DateTimeOffset]$Timestamp
    )

    Add-Type -AssemblyName System.IO.Compression | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

    $sourceRoot = [IO.Path]::GetFullPath($SourceDirectory).TrimEnd('\', '/')
    $zipTimestamp = $Timestamp.ToUniversalTime()
    $minimumZipTimestamp = [DateTimeOffset]::Parse("1980-01-01T00:00:00Z")
    $maximumZipTimestamp = [DateTimeOffset]::Parse("2107-12-31T23:59:58Z")
    if ($zipTimestamp -lt $minimumZipTimestamp) { $zipTimestamp = $minimumZipTimestamp }
    if ($zipTimestamp -gt $maximumZipTimestamp) { $zipTimestamp = $maximumZipTimestamp }

    $filePaths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File)) {
        $filePaths.Add($file.FullName)
    }
    $filePaths.Sort([StringComparer]::Ordinal)
    if ($filePaths.Count -eq 0) {
        throw "Cannot create an empty release archive from $sourceRoot"
    }

    $fileStream = [IO.File]::Open($DestinationPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $archive = New-Object System.IO.Compression.ZipArchive($fileStream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($filePath in $filePaths) {
                $relativeName = $filePath.Substring($sourceRoot.Length).TrimStart('\', '/').Replace('\', '/')
                $entry = $archive.CreateEntry($relativeName, [IO.Compression.CompressionLevel]::NoCompression)
                $entry.LastWriteTime = $zipTimestamp
                $input = [IO.File]::OpenRead($filePath)
                try {
                    $output = $entry.Open()
                    try {
                        $input.CopyTo($output)
                    } finally {
                        $output.Dispose()
                    }
                } finally {
                    $input.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $fileStream.Dispose()
    }
}

function Assert-PitchProxBinaryContainsASCII {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "Missing binary for $Description verification: $LiteralPath"
    }
    $binaryText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($LiteralPath))
    if ($binaryText.IndexOf($Value, [StringComparison]::Ordinal) -lt 0) {
        throw "Candidate binary does not contain the exact $Description value: $Value"
    }
}

function Resolve-PitchProxSafeOutputPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,
        [Parameter(Mandatory = $true)]
        [string]$TargetPath
    )

    $root = [IO.Path]::GetFullPath($RootPath).TrimEnd('\', '/')
    $target = [IO.Path]::GetFullPath($TargetPath)
    $prefix = $root + [IO.Path]::DirectorySeparatorChar
    if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe output path outside repository root: $target"
    }

    $relative = $target.Substring($prefix.Length)
    $current = $root
    foreach ($component in ($relative -split '[\\/]')) {
        if ([string]::IsNullOrWhiteSpace($component)) { continue }
        $current = Join-Path $current $component
        if (-not (Test-Path -LiteralPath $current)) { continue }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing output through a reparse point: $($item.FullName)"
        }
    }
    return $target
}

function Assert-PitchProxTreeContainsNoReparsePoints {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath)) { return }
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push([IO.Path]::GetFullPath($LiteralPath))
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing recursive removal because the tree contains a reparse point: $($item.FullName)"
        }
        if (-not $item.PSIsContainer) { continue }
        foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force)) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing recursive removal because the tree contains a reparse point: $($child.FullName)"
            }
            if ($child.PSIsContainer) { $pending.Push($child.FullName) }
        }
    }
}

function Assert-PitchProxWorkingTreeEOL {
    $issues = New-Object 'System.Collections.Generic.List[string]'
    $lines = @(Invoke-PitchProxNative -FilePath "git" -Arguments @("ls-files", "--eol") -FailureMessage "git ls-files --eol failed")
    foreach ($line in $lines) {
        if ([string]$line -notmatch '^\S+\s+w/(?<worktree>\S+)\s+attr/(?<attributes>.*?)\s*\t(?<path>.*)$') {
            continue
        }
        $worktree = $Matches.worktree
        $attributes = $Matches.attributes
        $path = $Matches.path
        if ($attributes -match '(?:^|\s)eol=lf(?:\s|$)' -and $worktree -notin @('lf', 'none')) {
            $issues.Add("$path (expected LF, got $worktree)")
        } elseif ($attributes -match '(?:^|\s)eol=crlf(?:\s|$)' -and $worktree -notin @('crlf', 'none')) {
            $issues.Add("$path (expected CRLF, got $worktree)")
        }
    }
    if ($issues.Count -gt 0) {
        throw "Working-tree line endings do not match .gitattributes:`n - $($issues -join "`n - ")"
    }
}

if ($Version -notmatch '^(?:v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?|dev-[0-9a-f]{7,40})$') {
    throw "Version must look like v0.44, v0.44-rc.1, or dev-1a2b3c4"
}
if ($SkipChecks -and -not $AllowDirty) {
    throw "-SkipChecks is allowed only together with -AllowDirty for a disposable diagnostic build."
}
if ($DownloadWinDivertArchive -and -not [string]::IsNullOrWhiteSpace($WinDivertArchivePath)) {
    throw "-DownloadWinDivertArchive and -WinDivertArchivePath are mutually exclusive."
}

$savedEnvironment = $null
$locationPushed = $false
Push-Location $repoRoot
$locationPushed = $true
try {
    $initialChanges = @(Invoke-PitchProxNative -FilePath "git" -Arguments @("status", "--porcelain=v1", "--untracked-files=all") -FailureMessage "git status failed")
    $workingTreeDirty = $initialChanges.Count -gt 0
    if ($workingTreeDirty -and -not $AllowDirty) {
        throw "Working tree is dirty. Commit the candidate or pass -AllowDirty only for a non-final test build."
    }

    $commit = (@(Invoke-PitchProxNative -FilePath "git" -Arguments @("rev-parse", "--verify", "HEAD") -FailureMessage "git rev-parse failed")[0]).Trim()
    $commitTimeText = (@(Invoke-PitchProxNative -FilePath "git" -Arguments @("show", "-s", "--format=%cI", "HEAD") -FailureMessage "git show failed")[0]).Trim()
    $commitTime = [DateTimeOffset]::Parse($commitTimeText, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)

    Assert-PitchProxWorkingTreeEOL

    $savedEnvironment = Enter-PitchProxBuildEnvironment
    $toolchain = Assert-PitchProxBuildToolchain -ExpectedModulePath (Join-Path $repoRoot "go.mod")

    $nodeVersion = "not-checked"
    if (-not $SkipChecks) {
        $nodeVersion = (@(Invoke-PitchProxNative -FilePath "node" -Arguments @("--version") -FailureMessage "node --version failed")[0]).Trim()
        if ($nodeVersion -ne $PitchProxReleaseSettings.NodeVersion) {
            throw "Node.js version mismatch: got $nodeVersion, want $($PitchProxReleaseSettings.NodeVersion)"
        }
        Invoke-PitchProxNative -FilePath "node" -Arguments @("--check", "internal\webui\dist\rules-ui.js") -FailureMessage "rules-ui.js syntax check failed"
        Invoke-PitchProxNative -FilePath "node" -Arguments @("--check", "internal\webui\dist\app.js") -FailureMessage "app.js syntax check failed"
        Invoke-PitchProxNative -FilePath "node" -Arguments @("--test", "internal\webui\rules_ui_test.js", "internal\webui\lifecycle_test.js") -FailureMessage "WebUI unit tests failed"
        Invoke-PitchProxNative -FilePath "go" -Arguments @("mod", "download") -FailureMessage "Go module download failed"
        Invoke-PitchProxNative -FilePath "go" -Arguments @("mod", "verify") -FailureMessage "Go module verification failed"
        Invoke-PitchProxNative -FilePath "go" -Arguments @("test", "-mod=readonly", "-count=1", "-cover", "./...") -FailureMessage "Go tests failed"
        Invoke-PitchProxNative -FilePath "go" -Arguments @("vet", "-mod=readonly", "./...") -FailureMessage "go vet failed"
        Invoke-PitchProxNative -FilePath "git" -Arguments @("diff", "--check") -FailureMessage "git diff --check failed"
        Invoke-PitchProxNative -FilePath "git" -Arguments @("show", "--check", "--format=", "HEAD") -FailureMessage "committed whitespace check failed"
    }

    $candidateRoot = Join-Path $repoRoot (Join-Path "build\candidates" $Version)
    $resolvedCandidate = Resolve-PitchProxSafeOutputPath -RootPath $repoRoot -TargetPath $candidateRoot
    if (Test-Path -LiteralPath $resolvedCandidate) {
        Assert-PitchProxTreeContainsNoReparsePoints -LiteralPath $resolvedCandidate
        Remove-Item -LiteralPath $resolvedCandidate -Recurse -Force
    }
    $packageDir = Join-Path $resolvedCandidate "package"
    New-Item -ItemType Directory -Force -Path $packageDir | Out-Null

    $trackedWinDivertLicense = Join-Path $repoRoot "licenses\WinDivert-LICENSE.txt"
    Assert-PitchProxFileSHA256 -LiteralPath $trackedWinDivertLicense -ExpectedSHA256 $PitchProxReleaseSettings.WinDivertLicenseSHA256 -Description "tracked WinDivert LICENSE"

    $runtimeWork = $null
    $winDivertDirectory = $repoRoot
    $winDivertRuntimeSource = "repository-root"
    $winDivertArchiveVerified = $false
    if ($DownloadWinDivertArchive -or -not [string]::IsNullOrWhiteSpace($WinDivertArchivePath)) {
        $runtimeWork = Join-Path $resolvedCandidate "_windivert"
        $runtimeExtract = Join-Path $runtimeWork "extracted"
        New-Item -ItemType Directory -Force -Path $runtimeExtract | Out-Null
        if ($DownloadWinDivertArchive) {
            $archivePath = Join-Path $runtimeWork "WinDivert-$($PitchProxReleaseSettings.WinDivertVersion)-A.zip"
            $oldProgressPreference = $ProgressPreference
            $ProgressPreference = "SilentlyContinue"
            try {
                $oldSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
                [Net.ServicePointManager]::SecurityProtocol = $oldSecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                try {
                    Invoke-WebRequest -UseBasicParsing -Uri $PitchProxReleaseSettings.WinDivertReleaseURL -OutFile $archivePath
                } finally {
                    [Net.ServicePointManager]::SecurityProtocol = $oldSecurityProtocol
                }
            } finally {
                $ProgressPreference = $oldProgressPreference
            }
        } else {
            $archiveItem = Get-Item -LiteralPath $WinDivertArchivePath -ErrorAction Stop
            if ($archiveItem.PSIsContainer) {
                throw "-WinDivertArchivePath must point to a ZIP file."
            }
            $archivePath = $archiveItem.FullName
        }
        Assert-PitchProxFileSHA256 -LiteralPath $archivePath -ExpectedSHA256 $PitchProxReleaseSettings.WinDivertArchiveSHA256 -Description "WinDivert release archive"
        Expand-Archive -LiteralPath $archivePath -DestinationPath $runtimeExtract -Force

        $archiveWinDivertDLL = Get-ChildItem -LiteralPath $runtimeExtract -Recurse -Filter "WinDivert.dll" -File |
            Where-Object { $_.FullName -match '[\\/]x64[\\/]WinDivert\.dll$' } |
            Select-Object -First 1
        $archiveWinDivertDriver = Get-ChildItem -LiteralPath $runtimeExtract -Recurse -Filter "WinDivert64.sys" -File |
            Where-Object { $_.FullName -match '[\\/]x64[\\/]WinDivert64\.sys$' } |
            Select-Object -First 1
        $archiveWinDivertLicense = Get-ChildItem -LiteralPath $runtimeExtract -Recurse -Filter "LICENSE" -File | Select-Object -First 1
        if ($null -eq $archiveWinDivertDLL -or $null -eq $archiveWinDivertDriver -or $null -eq $archiveWinDivertLicense) {
            throw "The verified WinDivert archive is missing its x64 runtime or LICENSE"
        }
        Assert-PitchProxFileSHA256 -LiteralPath $archiveWinDivertDLL.FullName -ExpectedSHA256 $PitchProxReleaseSettings.WinDivertDLLSHA256 -Description "archive WinDivert.dll"
        Assert-PitchProxFileSHA256 -LiteralPath $archiveWinDivertDriver.FullName -ExpectedSHA256 $PitchProxReleaseSettings.WinDivertDriverSHA256 -Description "archive WinDivert64.sys"
        Assert-PitchProxFileSHA256 -LiteralPath $archiveWinDivertLicense.FullName -ExpectedSHA256 $PitchProxReleaseSettings.WinDivertLicenseSHA256 -Description "archive WinDivert LICENSE"
        $winDivertDirectory = $archiveWinDivertDLL.DirectoryName
        $winDivertRuntimeSource = "verified-official-archive"
        $winDivertArchiveVerified = $true
    }

    foreach ($runtimeFile in @(
        @{ Name = "WinDivert.dll"; Hash = $PitchProxReleaseSettings.WinDivertDLLSHA256 },
        @{ Name = "WinDivert64.sys"; Hash = $PitchProxReleaseSettings.WinDivertDriverSHA256 }
    )) {
        Assert-PitchProxFileSHA256 -LiteralPath (Join-Path $winDivertDirectory $runtimeFile.Name) -ExpectedSHA256 $runtimeFile.Hash -Description $runtimeFile.Name
    }

    & (Join-Path $repoRoot "build.ps1") -Version $Version -OutputDirectory $packageDir -WinDivertDirectory $winDivertDirectory -RequireWinDivert
    if ($LASTEXITCODE -ne 0) { throw "Candidate build failed (exit code $LASTEXITCODE)" }

    foreach ($file in @("README.md", "CHECKS.md", "THIRD_PARTY_NOTICES.md")) {
        $source = Join-Path $repoRoot $file
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Missing required release document: $source"
        }
        Copy-Item -LiteralPath $source -Destination $packageDir
    }
    $docsSource = Join-Path $repoRoot "docs"
    if (-not (Test-Path -LiteralPath $docsSource -PathType Container)) {
        throw "Missing release documentation directory: $docsSource"
    }
    Copy-Item -LiteralPath $docsSource -Destination (Join-Path $packageDir "docs") -Recurse
    $packagedWinDivertLicense = Join-Path $packageDir "WinDivert-LICENSE.txt"
    Copy-Item -LiteralPath $trackedWinDivertLicense -Destination $packagedWinDivertLicense

    $goRoot = (@(Invoke-PitchProxNative -FilePath "go" -Arguments @("env", "GOROOT") -FailureMessage "Unable to locate the Go license")[0]).Trim()
    $goLicenseSource = Join-Path $goRoot "LICENSE"
    if (-not (Test-Path -LiteralPath $goLicenseSource -PathType Leaf)) {
        throw "Missing Go toolchain LICENSE: $goLicenseSource"
    }
    $packagedGoLicense = Join-Path $packageDir "Go-LICENSE.txt"
    Copy-Item -LiteralPath $goLicenseSource -Destination $packagedGoLicense

    $xsysDirectory = (@(Invoke-PitchProxNative -FilePath "go" -Arguments @("list", "-mod=readonly", "-m", "-f={{.Dir}}", "golang.org/x/sys") -FailureMessage "Unable to locate the golang.org/x/sys license")[0]).Trim()
    $xsysLicenseSource = Join-Path $xsysDirectory "LICENSE"
    if (-not (Test-Path -LiteralPath $xsysLicenseSource -PathType Leaf)) {
        throw "Missing golang.org/x/sys LICENSE: $xsysLicenseSource"
    }
    $packagedXsysLicense = Join-Path $packageDir "golang.org-x-sys-LICENSE.txt"
    Copy-Item -LiteralPath $xsysLicenseSource -Destination $packagedXsysLicense

    $releaseNotesOutputPath = Join-Path $resolvedCandidate "RELEASE_NOTES.md"
    if (-not [string]::IsNullOrWhiteSpace($ReleaseNotesSource)) {
        $releaseNotesSourcePath = if ([IO.Path]::IsPathRooted($ReleaseNotesSource)) {
            [IO.Path]::GetFullPath($ReleaseNotesSource)
        } else {
            [IO.Path]::GetFullPath((Join-Path $repoRoot $ReleaseNotesSource))
        }
        if (-not (Test-Path -LiteralPath $releaseNotesSourcePath -PathType Leaf)) {
            throw "Missing release notes: $releaseNotesSourcePath"
        }
        Copy-Item -LiteralPath $releaseNotesSourcePath -Destination $releaseNotesOutputPath
        $releaseNotesSourceDescription = $ReleaseNotesSource
    } elseif ($Version -match '^(?<release>v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?)(?:-|$)') {
        $releaseNotesName = "RELEASE_NOTES_$($Matches.release).md"
        $releaseNotesSourcePath = Join-Path $repoRoot (Join-Path "docs" $releaseNotesName)
        if (-not (Test-Path -LiteralPath $releaseNotesSourcePath -PathType Leaf)) {
            throw "Missing release notes for ${Version}: $releaseNotesSourcePath"
        }
        Copy-Item -LiteralPath $releaseNotesSourcePath -Destination $releaseNotesOutputPath
        $releaseNotesSourceDescription = "docs/$releaseNotesName"
    } else {
        $developmentNotes = @(
            "# pitchProx development artifact",
            "",
            "Version: ``$Version``",
            "Commit: ``$commit``",
            "",
            "This is an automated development artifact, not release notes for a stable version."
        ) -join "`n"
        Write-PitchProxUTF8NoBOM -LiteralPath $releaseNotesOutputPath -Value ($developmentNotes + "`n")
        $releaseNotesSourceDescription = "generated-development-note"
    }

    $builtExe = Join-Path $packageDir "pitchProx.exe"
    $moduleLines = @(Invoke-PitchProxNative -FilePath "go" -Arguments @("version", "-m", $builtExe) -FailureMessage "Unable to read candidate module metadata")
    $moduleMetadata = $moduleLines -join "`n"
    $normalizedModuleLines = @($moduleLines | ForEach-Object {
        $line = [string]$_
        $goMarker = $line.LastIndexOf(": go", [StringComparison]::Ordinal)
        if ($goMarker -ge 0) {
            "pitchProx.exe$($line.Substring($goMarker))"
        } else {
            $line
        }
    })
    foreach ($requiredMetadata in @(
        $PitchProxReleaseSettings.GoVersion,
        "build`tGOOS=$($PitchProxReleaseSettings.GOOS)",
        "build`tGOARCH=$($PitchProxReleaseSettings.GOARCH)",
        "build`tGOAMD64=$($PitchProxReleaseSettings.GOAMD64)",
        "build`tCGO_ENABLED=$($PitchProxReleaseSettings.CGOEnabled)",
        "build`tvcs.revision=$commit"
    )) {
        if ($moduleMetadata.IndexOf($requiredMetadata, [StringComparison]::Ordinal) -lt 0) {
            throw "Candidate metadata is missing: $requiredMetadata"
        }
    }
    Assert-PitchProxBinaryContainsASCII -LiteralPath $builtExe -Value $Version -Description "injected build version"
    $modifiedMatch = [regex]::Match($moduleMetadata, '(?m)^\s*build\s+vcs\.modified=(true|false)\s*$')
    if (-not $modifiedMatch.Success) {
        throw "Candidate metadata does not report vcs.modified"
    }
    $binaryVCSModified = $modifiedMatch.Groups[1].Value -eq "true"
    if (-not $AllowDirty -and $binaryVCSModified) {
        throw "A clean release candidate unexpectedly reports vcs.modified=true"
    }

    $postBuildChanges = @(Invoke-PitchProxNative -FilePath "git" -Arguments @("status", "--porcelain=v1", "--untracked-files=all") -FailureMessage "post-build git status failed")
    if (-not $AllowDirty -and $postBuildChanges.Count -gt 0) {
        throw "The release process changed tracked or untracked source files"
    }

    $standaloneExe = Join-Path $resolvedCandidate "pitchProx.exe"
    Copy-Item -LiteralPath $builtExe -Destination $standaloneExe
    $exeInfo = Get-Item -LiteralPath $standaloneExe
    $exeHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $standaloneExe).Hash.ToLowerInvariant()

    $manifest = [ordered]@{
        format = "pitchprox.build-manifest"
        format_version = 1
        version = $Version
        source = [ordered]@{
            commit = $commit
            commit_time_utc = $commitTime.ToUniversalTime().ToString("o")
            working_tree_dirty = $workingTreeDirty
            binary_vcs_modified = $binaryVCSModified
            checks_skipped = [bool]$SkipChecks
        }
        toolchain = [ordered]@{
            go = $toolchain.GoVersion
            node = $nodeVersion
        }
        target = [ordered]@{
            goos = $toolchain.GOOS
            goarch = $toolchain.GOARCH
            goamd64 = $toolchain.GOAMD64
            cgo_enabled = $toolchain.CGOEnabled
            gui_subsystem = $true
            trimpath = $true
            module_mode = "readonly"
            workspace_mode = $toolchain.GOWORK
            go_environment_file = $toolchain.GOENV
            goexperiment = $toolchain.GOEXPERIMENT
            gofips140 = $toolchain.GOFIPS140
        }
        windivert = [ordered]@{
            version = $PitchProxReleaseSettings.WinDivertVersion
            runtime_source = $winDivertRuntimeSource
            release_url = $PitchProxReleaseSettings.WinDivertReleaseURL
            archive_verified = $winDivertArchiveVerified
            expected_archive_sha256 = $PitchProxReleaseSettings.WinDivertArchiveSHA256
            verified_archive_sha256 = if ($winDivertArchiveVerified) { $PitchProxReleaseSettings.WinDivertArchiveSHA256 } else { $null }
            dll_sha256 = $PitchProxReleaseSettings.WinDivertDLLSHA256
            driver_sha256 = $PitchProxReleaseSettings.WinDivertDriverSHA256
            license_sha256 = $PitchProxReleaseSettings.WinDivertLicenseSHA256
        }
        licenses = [ordered]@{
            third_party_notices = "THIRD_PARTY_NOTICES.md"
            windivert_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $packagedWinDivertLicense).Hash.ToLowerInvariant()
            go_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $packagedGoLicense).Hash.ToLowerInvariant()
            golang_org_x_sys_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $packagedXsysLicense).Hash.ToLowerInvariant()
        }
        executable = [ordered]@{
            file = "pitchProx.exe"
            size = $exeInfo.Length
            sha256 = $exeHash
            injected_version_verified = $true
        }
        release_notes_source = $releaseNotesSourceDescription
        go_version_m = $normalizedModuleLines
    }
    $manifestJSON = ($manifest | ConvertTo-Json -Depth 8) + "`n"
    $packageManifest = Join-Path $packageDir "pitchProx-build-manifest.json"
    Write-PitchProxUTF8NoBOM -LiteralPath $packageManifest -Value $manifestJSON
    $manifestPath = Join-Path $resolvedCandidate "pitchProx-build-manifest.json"
    Copy-Item -LiteralPath $packageManifest -Destination $manifestPath

    if ($null -ne $runtimeWork -and (Test-Path -LiteralPath $runtimeWork)) {
        Remove-Item -LiteralPath $runtimeWork -Recurse -Force
    }

    $zipPath = Join-Path $resolvedCandidate "pitchProx-windows-amd64.zip"
    New-PitchProxDeterministicZip -SourceDirectory $packageDir -DestinationPath $zipPath -Timestamp $commitTime

    $hashPath = Join-Path $resolvedCandidate "pitchProx-windows-amd64.sha256"
    $hashLines = @($standaloneExe, $zipPath, $manifestPath) | ForEach-Object {
        $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $_
        "{0} *{1}" -f $hash.Hash.ToLowerInvariant(), (Split-Path $hash.Path -Leaf)
    }
    Write-PitchProxUTF8NoBOM -LiteralPath $hashPath -Value (($hashLines -join "`n") + "`n")

    Write-Host "Release candidate prepared in $resolvedCandidate"
    Get-ChildItem -LiteralPath $resolvedCandidate -File | Select-Object Name, Length
} finally {
    if ($null -ne $savedEnvironment) {
        Exit-PitchProxBuildEnvironment -SavedEnvironment $savedEnvironment
    }
    if ($locationPushed) {
        Pop-Location
    }
}
