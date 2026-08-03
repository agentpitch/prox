param(
    [string]$Version = "",
    [string]$OutputDirectory = "build",
    [string]$OutputName = "pitchProx.exe",
    [string]$WinDivertDirectory = "",
    [switch]$RequireWinDivert
)

$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot
. (Join-Path $repoRoot "tools\release-common.ps1")

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = if ([string]::IsNullOrWhiteSpace($env:PITCHPROX_VERSION)) { "dev" } else { $env:PITCHPROX_VERSION.Trim() }
}
if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z._+-]*$') {
    throw "Version contains unsupported characters: $Version"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    throw "OutputDirectory is required"
}
if ([string]::IsNullOrWhiteSpace($OutputName) -or [IO.Path]::GetFileName($OutputName) -ne $OutputName) {
    throw "OutputName must be a file name"
}

if ([IO.Path]::IsPathRooted($OutputDirectory)) {
    $outputPath = [IO.Path]::GetFullPath($OutputDirectory)
} else {
    $outputPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDirectory))
}
if ([string]::IsNullOrWhiteSpace($WinDivertDirectory)) {
    $WinDivertDirectory = $repoRoot
} elseif (-not [IO.Path]::IsPathRooted($WinDivertDirectory)) {
    $WinDivertDirectory = Join-Path $repoRoot $WinDivertDirectory
}
$WinDivertDirectory = [IO.Path]::GetFullPath($WinDivertDirectory)

$runtimeFiles = @(
    [pscustomobject]@{
        Name = "WinDivert.dll"
        Hash = $PitchProxReleaseSettings.WinDivertDLLSHA256
    },
    [pscustomobject]@{
        Name = "WinDivert64.sys"
        Hash = $PitchProxReleaseSettings.WinDivertDriverSHA256
    }
)
$availableRuntimeFiles = @()
foreach ($runtimeFile in $runtimeFiles) {
    $source = Join-Path $WinDivertDirectory $runtimeFile.Name
    $existingDestination = [IO.Path]::GetFullPath((Join-Path $outputPath $runtimeFile.Name))
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Assert-PitchProxFileSHA256 -LiteralPath $source -ExpectedSHA256 $runtimeFile.Hash -Description "WinDivert $($runtimeFile.Name)"
        $availableRuntimeFiles += [pscustomobject]@{ Name = $runtimeFile.Name; Source = $source }
    } elseif (Test-Path -LiteralPath $existingDestination -PathType Leaf) {
        Assert-PitchProxFileSHA256 -LiteralPath $existingDestination -ExpectedSHA256 $runtimeFile.Hash -Description "existing output WinDivert $($runtimeFile.Name)"
        $availableRuntimeFiles += [pscustomobject]@{ Name = $runtimeFile.Name; Source = $existingDestination }
    } elseif ($RequireWinDivert) {
        throw "Missing required WinDivert runtime file: $source"
    }
}

$savedEnvironment = Enter-PitchProxBuildEnvironment
$locationPushed = $false
try {
    Push-Location $repoRoot
    $locationPushed = $true
    $toolchain = Assert-PitchProxBuildToolchain -ExpectedModulePath (Join-Path $repoRoot "go.mod")
    New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
    $exePath = Join-Path $outputPath $OutputName
    $ldflags = "-H=windowsgui -s -w -X github.com/agentpitch/prox/internal/buildinfo.Version=$Version"

    Invoke-PitchProxNative -FilePath "go" -Arguments @(
        "build",
        "-mod=readonly",
        "-trimpath",
        "-buildvcs=true",
        "-ldflags", $ldflags,
        "-o", $exePath,
        ".\cmd\pitchprox"
    ) -FailureMessage "go build failed"

    foreach ($runtimeFile in $availableRuntimeFiles) {
        $runtimeDestination = [IO.Path]::GetFullPath((Join-Path $outputPath $runtimeFile.Name))
        if (-not $runtimeFile.Source.Equals($runtimeDestination, [StringComparison]::OrdinalIgnoreCase)) {
            Copy-Item -LiteralPath $runtimeFile.Source -Destination $runtimeDestination -Force
        }
    }
} finally {
    if ($locationPushed) {
        Pop-Location
    }
    Exit-PitchProxBuildEnvironment -SavedEnvironment $savedEnvironment
}

Write-Host "Built $exePath (version $Version, $($toolchain.GoVersion), windows/amd64, CGO_ENABLED=0, GUI subsystem)"
foreach ($runtimeFile in $runtimeFiles) {
    if ($runtimeFile.Name -notin @($availableRuntimeFiles | ForEach-Object { $_.Name })) {
        Write-Warning "Missing $($runtimeFile.Name). Download the exact WinDivert $($PitchProxReleaseSettings.WinDivertVersion) runtime from $($PitchProxReleaseSettings.WinDivertReleasePage)"
    }
}
