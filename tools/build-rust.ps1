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
$verified = @()
foreach ($file in @(
    @{ Name = "WinDivert.dll"; Hash = $PitchProxReleaseSettings.WinDivertDLLSHA256 },
    @{ Name = "WinDivert64.sys"; Hash = $PitchProxReleaseSettings.WinDivertDriverSHA256 }
)) {
    $source = Join-Path $runtime $file.Name
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) {
        $source = Join-Path $output $file.Name
    }
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Assert-PitchProxFileSHA256 -LiteralPath $source -ExpectedSHA256 $file.Hash -Description $file.Name
        $verified += @{ Name = $file.Name; Source = $source }
    } elseif ($RequireWinDivert) {
        throw "Missing required WinDivert runtime file: $($file.Name)"
    } else {
        Write-Warning "Missing $($file.Name). Use the verified WinDivert $($PitchProxReleaseSettings.WinDivertVersion) runtime for interception."
    }
}

$previousVersion = $env:PITCHPROX_VERSION
$targetDirectory = Join-Path $repo "target"
$previousTargetDirectory = $env:CARGO_TARGET_DIR
try {
    $env:PITCHPROX_VERSION = $Version
    $env:CARGO_TARGET_DIR = $targetDirectory
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
}

[IO.Directory]::CreateDirectory($output) | Out-Null
$executable = Join-Path $output "pitchProx.exe"
Copy-Item -LiteralPath (Join-Path $targetDirectory "$Target/release/pitchProx.exe") -Destination $executable -Force
foreach ($file in $verified) {
    $destination = Join-Path $output $file.Name
    if (![string]::Equals($destination, $file.Source, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $file.Source -Destination $destination -Force
    }
}
Write-Host "Built $executable (Rust $Target, version $Version)"
