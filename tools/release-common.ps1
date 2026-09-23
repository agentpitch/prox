$PitchProxReleaseSettings = [ordered]@{
    GoVersion                = "go1.26.8"
    NodeVersion              = "v22.17.0"
    GOOS                     = "windows"
    GOARCH                   = "amd64"
    GOAMD64                  = "v1"
    CGOEnabled               = "0"
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
