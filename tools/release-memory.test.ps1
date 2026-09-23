$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "release-common.ps1")

$testRoot = Join-Path (Split-Path -Parent $PSScriptRoot) ("build\release-memory-tests\" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
$testFiles = New-Object 'System.Collections.Generic.List[string]'
$passed = 0

function New-TestPE {
    param([string]$Name, [uint32]$VirtualSize = 500000, [uint16]$Subsystem = 2, [uint16]$SectionCount = 1)

    $bytes = New-Object byte[] 2048
    [BitConverter]::GetBytes([uint16]0x5a4d).CopyTo($bytes, 0)
    [BitConverter]::GetBytes([uint32]128).CopyTo($bytes, 0x3c)
    [BitConverter]::GetBytes([uint32]0x00004550).CopyTo($bytes, 128)
    [BitConverter]::GetBytes([uint16]0x8664).CopyTo($bytes, 132)
    [BitConverter]::GetBytes($SectionCount).CopyTo($bytes, 134)
    [BitConverter]::GetBytes([uint16]240).CopyTo($bytes, 148)
    [BitConverter]::GetBytes([uint16]0x20b).CopyTo($bytes, 152)
    [BitConverter]::GetBytes($Subsystem).CopyTo($bytes, 220)
    [Text.Encoding]::ASCII.GetBytes(".data").CopyTo($bytes, 392)
    [BitConverter]::GetBytes($VirtualSize).CopyTo($bytes, 400)
    [BitConverter]::GetBytes([uint32]4096).CopyTo($bytes, 404)
    [BitConverter]::GetBytes([uint32]512).CopyTo($bytes, 408)
    [BitConverter]::GetBytes([uint32]1024).CopyTo($bytes, 412)
    [BitConverter]::GetBytes([uint32]3221225536).CopyTo($bytes, 428) # readable, writable, initialized data
    $path = Join-Path $testRoot $Name
    [IO.File]::WriteAllBytes($path, $bytes)
    $testFiles.Add($path)
    return $path
}

function Assert-Rejected {
    param([scriptblock]$Action, [string]$Expected)
    try { & $Action | Out-Null } catch {
        if ($_.Exception.Message -notlike $Expected) { throw }
        $script:passed++
        return
    }
    throw "Expected rejection: $Expected"
}

try {
    $small = New-TestPE -Name "small.exe"
    $layout = Assert-PitchProxLeanBinary -LiteralPath $small
    if ($layout.data_virtual_bytes -ne 500000 -or $layout.data_raw_bytes -ne 512 -or $layout.writable_static_bytes -ne 500000) {
        throw "PE verifier confused file size with virtual static memory"
    }
    $passed++
    $atLimit = New-TestPE -Name "limit.exe" -VirtualSize 2MB
    $null = Assert-PitchProxLeanBinary -LiteralPath $atLimit
    $passed++
    $heavy = New-TestPE -Name "large-bss.exe" -VirtualSize 32MB
    Assert-Rejected { Assert-PitchProxLeanBinary -LiteralPath $heavy } "Static memory regression:*"
    $extraWritable = New-TestPE -Name "other-writable.exe" -SectionCount 2
    $bytes = [IO.File]::ReadAllBytes($extraWritable)
    [Text.Encoding]::ASCII.GetBytes(".bss").CopyTo($bytes, 432)
    [BitConverter]::GetBytes([uint32]32MB).CopyTo($bytes, 440)
    [BitConverter]::GetBytes([uint32]3221225536).CopyTo($bytes, 468)
    [IO.File]::WriteAllBytes($extraWritable, $bytes)
    Assert-Rejected { Assert-PitchProxLeanBinary -LiteralPath $extraWritable } "Static memory regression:*"
    $console = New-TestPE -Name "console.exe" -Subsystem 3
    Assert-Rejected { Assert-PitchProxLeanBinary -LiteralPath $console } "Candidate does not use the Windows GUI subsystem"
    $badTable = New-TestPE -Name "bad-table.exe" -SectionCount 96
    Assert-Rejected { Assert-PitchProxLeanBinary -LiteralPath $badTable } "Invalid PE section table*"
    $rawOverflow = New-TestPE -Name "raw-overflow.exe"
    $bytes = [IO.File]::ReadAllBytes($rawOverflow)
    [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($bytes, 412)
    [IO.File]::WriteAllBytes($rawOverflow, $bytes)
    Assert-Rejected { Assert-PitchProxLeanBinary -LiteralPath $rawOverflow } "Invalid raw section range*"
    $short = Join-Path $testRoot "truncated.exe"
    [IO.File]::WriteAllBytes($short, (New-Object byte[] 32))
    $testFiles.Add($short)
    Assert-Rejected { Assert-PitchProxLeanBinary -LiteralPath $short } "Invalid DOS header*"

    # Exercise dependency admission without depending on the local compiler or
    # test-only packages. Each of these imports must independently block release.
    function Invoke-PitchProxNative { return $script:TestDependencies }
    $script:TestDependencies = @("runtime", "github.com/agentpitch/prox/cmd/pitchprox")
    Assert-PitchProxLeanDependencies
    $passed++
    foreach ($dependency in @("crypto/internal/fips140/drbg", "crypto/rand", "crypto/sha256", "crypto/tls", "net/http", "modernc.org/sqlite", "modernc.org/libc")) {
        $script:TestDependencies = @("runtime", $dependency)
        Assert-Rejected { Assert-PitchProxLeanDependencies } "Production dependency memory regression:*"
    }
    Write-Host "Release memory gate: $passed checks passed"
} finally {
    $root = [IO.Path]::GetFullPath($testRoot).TrimEnd('\')
    foreach ($file in $testFiles) {
        $resolved = [IO.Path]::GetFullPath($file)
        if (!$resolved.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Unsafe test cleanup: $resolved" }
        Remove-Item -LiteralPath $resolved -Force
    }
    # The directory is now empty; no recursive deletion of computed paths.
    Remove-Item -LiteralPath $root
}
