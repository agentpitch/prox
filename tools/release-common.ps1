$PitchProxReleaseSettings = [ordered]@{
    GoVersion                = "go1.26.8"
    NodeVersion              = "v22.17.0"
    GOOS                     = "windows"
    GOARCH                   = "amd64"
    GOAMD64                  = "v1"
    CGOEnabled               = "0"
    MaxWritableStaticBytes   = 2MB
    WinDivertVersion         = "2.2.2"
    WinDivertReleaseURL      = "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip"
    WinDivertReleasePage     = "https://github.com/basil00/WinDivert/releases/tag/v2.2.2"
    WinDivertArchiveSHA256   = "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15"
    WinDivertDLLSHA256       = "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"
    WinDivertDriverSHA256    = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"
    WinDivertLicenseSHA256   = "14a0cb5214d536e4fdae6aa3f5696f981eeda106cd026e9794bba489ee79d628"
}

function Invoke-PitchProxNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [string]$FailureMessage = "Native command failed"
    )

    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$FailureMessage (exit code $exitCode)"
    }
}

function Enter-PitchProxBuildEnvironment {
    $names = @("GOTOOLCHAIN", "GOOS", "GOARCH", "GOAMD64", "CGO_ENABLED", "GOFLAGS", "GOWORK", "GOENV", "GOEXPERIMENT", "GOFIPS140")
    $saved = @{}
    foreach ($name in $names) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }

    $env:GOTOOLCHAIN = $PitchProxReleaseSettings.GoVersion
    $env:GOOS = $PitchProxReleaseSettings.GOOS
    $env:GOARCH = $PitchProxReleaseSettings.GOARCH
    $env:GOAMD64 = $PitchProxReleaseSettings.GOAMD64
    $env:CGO_ENABLED = $PitchProxReleaseSettings.CGOEnabled
    $env:GOFLAGS = "-mod=readonly"
    $env:GOWORK = "off"
    $env:GOENV = "off"
    $env:GOEXPERIMENT = ""
    $env:GOFIPS140 = "off"
    return $saved
}

function Exit-PitchProxBuildEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$SavedEnvironment
    )

    foreach ($name in $SavedEnvironment.Keys) {
        $value = $SavedEnvironment[$name]
        if ($null -eq $value) {
            [Environment]::SetEnvironmentVariable($name, $null, "Process")
        } else {
            [Environment]::SetEnvironmentVariable($name, [string]$value, "Process")
        }
    }
}

function Assert-PitchProxBuildToolchain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExpectedModulePath
    )

    $values = @(Invoke-PitchProxNative -FilePath "go" -Arguments @("env", "GOVERSION", "GOOS", "GOARCH", "GOAMD64", "CGO_ENABLED") -FailureMessage "go env failed")
    if ($values.Count -ne 5) {
        throw "Unexpected go env output: $($values -join ', ')"
    }

    $expected = @(
        $PitchProxReleaseSettings.GoVersion,
        $PitchProxReleaseSettings.GOOS,
        $PitchProxReleaseSettings.GOARCH,
        $PitchProxReleaseSettings.GOAMD64,
        $PitchProxReleaseSettings.CGOEnabled
    )
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ([string]$values[$index] -ne [string]$expected[$index]) {
            throw "Unexpected Go build environment at index ${index}: got '$($values[$index])', want '$($expected[$index])'"
        }
    }

    $goWork = (@(Invoke-PitchProxNative -FilePath "go" -Arguments @("env", "GOWORK") -FailureMessage "go env GOWORK failed") -join "").Trim()
    if ($goWork -ne "off") {
        throw "Unexpected Go workspace mode: got '$goWork', want 'off'"
    }
    $goEnv = (@(Invoke-PitchProxNative -FilePath "go" -Arguments @("env", "GOENV") -FailureMessage "go env GOENV failed") -join "").Trim()
    # With process GOENV=off, Go intentionally reports no environment-file
    # path. Check both the controlling process variable and that empty result.
    if ($env:GOENV -ne "off" -or $goEnv -ne "") {
        throw "Unexpected Go environment-file mode: process GOENV='$env:GOENV', go env GOENV='$goEnv'"
    }
    $goExperiment = (@(Invoke-PitchProxNative -FilePath "go" -Arguments @("env", "GOEXPERIMENT") -FailureMessage "go env GOEXPERIMENT failed") -join "").Trim()
    if ($goExperiment -ne "") {
        throw "Unexpected GOEXPERIMENT value: '$goExperiment'"
    }
    $goFIPS140 = (@(Invoke-PitchProxNative -FilePath "go" -Arguments @("env", "GOFIPS140") -FailureMessage "go env GOFIPS140 failed") -join "").Trim()
    if ($goFIPS140 -ne "off") {
        throw "Unexpected GOFIPS140 value: got '$goFIPS140', want 'off'"
    }
    $goMod = (@(Invoke-PitchProxNative -FilePath "go" -Arguments @("env", "GOMOD") -FailureMessage "go env GOMOD failed") -join "").Trim()
    $expectedGoMod = [IO.Path]::GetFullPath($ExpectedModulePath)
    if ([string]::IsNullOrWhiteSpace($goMod) -or -not [IO.Path]::GetFullPath($goMod).Equals($expectedGoMod, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unexpected Go module: got '$goMod', want '$expectedGoMod'"
    }

    return [pscustomobject]@{
        GoVersion  = [string]$values[0]
        GOOS       = [string]$values[1]
        GOARCH     = [string]$values[2]
        GOAMD64    = [string]$values[3]
        CGOEnabled = [string]$values[4]
        GOWORK      = $goWork
        GOENV       = "off"
        GOEXPERIMENT = $goExperiment
        GOFIPS140   = $goFIPS140
    }
}

function Assert-PitchProxLeanDependencies {
    # Check only the shipped command: test servers may legitimately use net/http
    # and TLS. A standard-library import alone can reserve tens of MiB of static
    # memory, so checking go.mod or the compressed executable size is insufficient.
    $dependencies = @(Invoke-PitchProxNative -FilePath "go" -Arguments @("list", "-mod=readonly", "-deps", "./cmd/pitchprox") -FailureMessage "Unable to inspect production dependencies")
    $forbidden = @(
        "crypto/internal/fips140/drbg",
        "crypto/rand",
        "crypto/sha256",
        "crypto/tls",
        "net/http",
        "modernc.org/sqlite",
        "modernc.org/libc"
    )
    $present = @($forbidden | Where-Object { $_ -in $dependencies })
    if ($present.Count -gt 0) {
        throw "Production dependency memory regression: $($present -join ', '). Use the platform crypto/HTTP adapters; do not disable this gate to ship a heavy runtime."
    }
}

function Assert-PitchProxLeanBinary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    # Read only DOS, PE and section headers. In particular, do not mistake the
    # small raw .data section for the much larger zero-initialized virtual data.
    $stream = [IO.File]::OpenRead($LiteralPath)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) {
            throw "Invalid DOS header in candidate executable"
        }
        $stream.Position = 0x3c
        $peOffset = [long]$reader.ReadUInt32()
        if ($peOffset -lt 64 -or $peOffset + 24 -gt $stream.Length) {
            throw "Invalid PE header offset in candidate executable"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw "Candidate is not a Windows amd64 PE executable"
        }
        $sectionCount = $reader.ReadUInt16()
        $stream.Position = $peOffset + 20
        $optionalSize = $reader.ReadUInt16()
        $sectionTable = $peOffset + 24 + $optionalSize
        if ($sectionCount -lt 1 -or $sectionCount -gt 96 -or $optionalSize -lt 70 -or $sectionTable + 40 * $sectionCount -gt $stream.Length) {
            throw "Invalid PE section table in candidate executable"
        }
        $stream.Position = $peOffset + 24
        if ($reader.ReadUInt16() -ne 0x20b) {
            throw "Candidate is not a PE32+ executable"
        }
        $stream.Position = $peOffset + 24 + 68
        if ($reader.ReadUInt16() -ne 2) {
            throw "Candidate does not use the Windows GUI subsystem"
        }
        $dataSections = 0
        [long]$dataVirtualBytes = 0
        [long]$dataRawBytes = 0
        [long]$writableVirtualBytes = 0
        for ($index = 0; $index -lt $sectionCount; $index++) {
            $stream.Position = $sectionTable + 40 * $index
            $name = [Text.Encoding]::ASCII.GetString($reader.ReadBytes(8)).TrimEnd([char]0)
            $virtualSize = [long]$reader.ReadUInt32()
            $null = $reader.ReadUInt32() # VirtualAddress
            $rawSize = [long]$reader.ReadUInt32()
            $rawOffset = [long]$reader.ReadUInt32()
            $stream.Position = $sectionTable + 40 * $index + 36
            $characteristics = [long]$reader.ReadUInt32()
            if ($rawSize -gt 0 -and ($rawOffset -lt $sectionTable + 40 * $sectionCount -or $rawOffset + $rawSize -gt $stream.Length)) {
                throw "Invalid raw section range in candidate executable: $name"
            }
            if (($characteristics -band 2147483648) -ne 0) {
                $writableVirtualBytes += [Math]::Max($virtualSize, $rawSize)
            }
            if ($name -eq ".data") {
                $dataSections++
                $dataVirtualBytes = $virtualSize
                $dataRawBytes = $rawSize
            }
        }
        if ($dataSections -ne 1 -or $dataVirtualBytes -le 0) {
            throw "Candidate must contain exactly one nonempty .data section"
        }
        if ($dataVirtualBytes -gt $PitchProxReleaseSettings.MaxWritableStaticBytes -or $writableVirtualBytes -gt $PitchProxReleaseSettings.MaxWritableStaticBytes) {
            throw "Static memory regression: .data VirtualSize=$dataVirtualBytes, writable sections=$writableVirtualBytes; limit=$($PitchProxReleaseSettings.MaxWritableStaticBytes) bytes"
        }
        return [pscustomobject][ordered]@{
            data_virtual_bytes = $dataVirtualBytes
            data_raw_bytes = $dataRawBytes
            writable_static_bytes = $writableVirtualBytes
            writable_static_limit_bytes = $PitchProxReleaseSettings.MaxWritableStaticBytes
        }
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Assert-PitchProxFileSHA256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSHA256,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "Missing $Description at $LiteralPath"
    }
    $actual = $null
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $LiteralPath -ErrorAction Stop).Hash.ToLowerInvariant()
            break
        } catch {
            if ($attempt -eq 5) {
                throw "Unable to read $Description for SHA-256 verification at ${LiteralPath}: $($_.Exception.Message)"
            }
            Start-Sleep -Milliseconds 200
        }
    }
    $expected = $ExpectedSHA256.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "$Description SHA-256 mismatch: got $actual, want $expected"
    }
}

function Write-PitchProxUTF8NoBOM {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($LiteralPath, $Value, $encoding)
}
