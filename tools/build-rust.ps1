param(
    [string]$Version = "",
    [string]$OutputDirectory = "build/rust",
    [ValidateSet("x86_64-pc-windows-gnu", "x86_64-pc-windows-msvc")]
    [string]$Target = "x86_64-pc-windows-gnu",
    [string]$WinDivertDirectory = "",
    [switch]$RequireWinDivert
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "release-common.ps1")

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = if ([string]::IsNullOrWhiteSpace($env:PITCHPROX_VERSION)) { "dev" } else { $env:PITCHPROX_VERSION.Trim() }
}
if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z._+-]*$') {
    throw "Version contains unsupported characters: $Version"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { throw "OutputDirectory is required" }
if ([string]::IsNullOrWhiteSpace($WinDivertDirectory)) { $WinDivertDirectory = $repo }

function Resolve-BuildDirectory([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $repo $Path))
}

$output = Resolve-BuildDirectory $OutputDirectory
$runtime = Resolve-BuildDirectory $WinDivertDirectory
$driverName = "WinDivert64.sys"
$driver = Join-Path $runtime $driverName
$driverDestination = Join-Path $output $driverName
if (!(Test-Path -LiteralPath $driver -PathType Leaf)) { $driver = $driverDestination }
$driverPresent = Test-Path -LiteralPath $driver -PathType Leaf
if ($driverPresent) {
    Assert-PitchProxFileSHA256 -LiteralPath $driver -ExpectedSHA256 $PitchProxReleaseSettings.WinDivertDriverSHA256 -Description $driverName
} elseif ($RequireWinDivert) {
    throw "Missing required WinDivert driver: $driverName"
} else {
    Write-Warning "Missing $driverName. This development build requires an external driver file for interception."
}

$previousVersion = $env:PITCHPROX_VERSION
$targetDirectory = Join-Path $repo "target"
$previousTargetDirectory = $env:CARGO_TARGET_DIR
$previousDriver = $env:PITCHPROX_WINDIVERT_DRIVER
try {
    $env:PITCHPROX_VERSION = $Version
    $env:CARGO_TARGET_DIR = $targetDirectory
    $env:PITCHPROX_WINDIVERT_DRIVER = if ($driverPresent) { $driver } else { $null }
    Push-Location $repo
    try {
        & cargo build --locked --release --target $Target --bin pitchProx
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
} finally {
    $env:PITCHPROX_VERSION = $previousVersion
    $env:CARGO_TARGET_DIR = $previousTargetDirectory
    $env:PITCHPROX_WINDIVERT_DRIVER = $previousDriver
}

[IO.Directory]::CreateDirectory($output) | Out-Null
$executable = Join-Path $output "pitchProx.exe"
Copy-Item -LiteralPath (Join-Path $targetDirectory "$Target/release/pitchProx.exe") -Destination $executable -Force
Write-Host "Built $executable (Rust $Target, version $Version)"
