param(
    [Parameter(Mandatory = $true)]
    [string]$GoExecutable,
    [string]$RustExecutable,
    [ValidateRange(5, 300)]
    [int]$Seconds = 20,
    [ValidateRange(1, 10)]
    [int]$Repeats = 3,
    [switch]$UseTray
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$runDirectory = Join-Path $repo ('build/runtime-comparison/' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($runDirectory) | Out-Null

function New-LoopbackPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return $listener.LocalEndpoint.Port
    } finally {
        $listener.Stop()
    }
}

function Measure-Median($Values) {
    $ordered = @($Values | Sort-Object)
    $middle = [int][Math]::Floor($ordered.Count / 2)
    if ($ordered.Count % 2) { return $ordered[$middle] }
    return ($ordered[$middle - 1] + $ordered[$middle]) / 2
}

function Measure-Runtime($Name, $Executable, $Attempt) {
    $directory = Join-Path $runDirectory "$Name-$Attempt"
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $isolatedExecutable = Join-Path $directory 'pitchProx.exe'
    Copy-Item -LiteralPath $Executable -Destination $isolatedExecutable
    $configPath = Join-Path $directory 'pitchProx.config.json'
    $port = New-LoopbackPort
    $config = @{
        version = 1
        retention_minutes = 7
        dropped_log_max_bytes = 10485760
        http = @{ listen = "127.0.0.1:$port" }
        transparent = @{ ipv4_listener = '0.0.0.0'; ipv6_listener = '::'; listener_port = 26001; sniff_bytes = 4096; sniff_timeout_ms = 1500 }
        proxies = $null
        chains = @()
        rules = @(
            @{ id = 'localhost'; name = 'Localhost / This PC'; enabled = $true; applications = '*'; target_hosts = 'localhost; 127.0.0.1; ::1; %ComputerName%'; target_ports = 'Any'; action = 'direct'; notes = 'Bypass loopback and this machine.' },
            @{ id = 'default'; name = 'Default'; enabled = $true; applications = '*'; target_hosts = 'Any'; target_ports = 'Any'; action = 'direct' }
        )
    }
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 8))

    $launch = [Diagnostics.ProcessStartInfo]::new($isolatedExecutable, 'run')
    $launch.WorkingDirectory = $directory
    $launch.UseShellExecute = $false
    $launch.CreateNoWindow = $true
    $launch.RedirectStandardError = $true
    $launch.EnvironmentVariables['PITCHPROX_CONFIG'] = $configPath
    $launch.EnvironmentVariables['PITCHPROX_HISTORY'] = Join-Path $directory 'pitchProx.history'
    $launch.EnvironmentVariables['PITCHPROX_ALLOW_UNELEVATED'] = '1'
    $launch.EnvironmentVariables['PITCHPROX_DISABLE_TRAY'] = if ($UseTray) { '0' } else { '1' }
    $launch.EnvironmentVariables['MYPROX_DISABLE_TRAY'] = '0'
    $launch.EnvironmentVariables['PITCHPROX_RESOURCE_LOG'] = 'off'

    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $handler.AllowAutoRedirect = $false
    $http = [Net.Http.HttpClient]::new($handler)
    $http.Timeout = [TimeSpan]::FromSeconds(2)
    $origin = "http://127.0.0.1:$port"
    $process = $null
    $healthy = $false
    try {
        $startup = [Diagnostics.Stopwatch]::StartNew()
        $process = [Diagnostics.Process]::Start($launch)
        $stderr = $process.StandardError.ReadToEndAsync()
        do {
            if ($process.HasExited) { throw "$Name exited early ($($process.ExitCode)). $($stderr.GetAwaiter().GetResult())" }
            $health = $null
            try {
                $health = $http.GetStringAsync("$origin/api/health").GetAwaiter().GetResult() | ConvertFrom-Json
            } catch {
                Start-Sleep -Milliseconds 25
            }
            if ($health.ok -and $health.pid -eq $process.Id) {
                $healthy = $true
                break
            }
        } while ($startup.Elapsed.TotalSeconds -lt 15)
        if (!$healthy) { throw "$Name did not report a healthy matching PID" }
        $startup.Stop()

        $http.DefaultRequestHeaders.Add('X-PitchProx-WebUI', '1')
        Start-Sleep -Seconds 3
        foreach ($scenario in @('idle', 'snapshot-at-2hz')) {
            if ($scenario -ne 'idle') {
                $null = $http.GetStringAsync("$origin/api/snapshot?include_logs=0").GetAwaiter().GetResult()
            }
            $process.Refresh()
            $cpuStart = $process.TotalProcessorTime
            $clock = [Diagnostics.Stopwatch]::StartNew()
            $private = @()
            $working = @()
            $threads = @()
            $handles = @()
            $latency = @()
            for ($sample = 0; $sample -lt ($Seconds * 2); $sample++) {
                if ($scenario -ne 'idle') {
                    $request = [Diagnostics.Stopwatch]::StartNew()
                    $snapshot = $http.GetStringAsync("$origin/api/snapshot?include_logs=0").GetAwaiter().GetResult()
                    $latency += $request.Elapsed.TotalMilliseconds
                    if ($sample -eq 0) {
                        $data = $snapshot | ConvertFrom-Json
                        if ($data.retention_minutes -ne 7) { throw "$Name returned an invalid snapshot" }
                    }
                }
                $process.Refresh()
                $private += $process.PrivateMemorySize64
                $working += $process.WorkingSet64
                $threads += $process.Threads.Count
                $handles += $process.HandleCount
                $remaining = 500 * ($sample + 1) - $clock.Elapsed.TotalMilliseconds
                if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int]$remaining) }
            }
            $process.Refresh()
            $cpuMilliseconds = ($process.TotalProcessorTime - $cpuStart).TotalMilliseconds
            [pscustomobject]@{
                implementation = $Name
                version = $health.version
                tray = [bool]$UseTray
                attempt = $Attempt
                scenario = $scenario
                startup_ms = [Math]::Round($startup.Elapsed.TotalMilliseconds, 2)
                elapsed_seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 3)
                cpu_ms = [Math]::Round($cpuMilliseconds, 3)
                cpu_one_core_percent = [Math]::Round(100 * $cpuMilliseconds / $clock.Elapsed.TotalMilliseconds, 4)
                private_bytes_median = Measure-Median $private
                working_set_bytes_median = Measure-Median $working
                threads_median = Measure-Median $threads
                handles_median = Measure-Median $handles
                snapshot_latency_ms_median = if ($latency.Count) { [Math]::Round((Measure-Median $latency), 3) } else { $null }
                executable_bytes = (Get-Item -LiteralPath $Executable).Length
            }
        }
    } finally {
        if ($process) {
            if (!$process.HasExited -and $healthy) {
                try {
                    $response = $http.PostAsync("$origin/api/control/stop", $null).GetAwaiter().GetResult()
                    $response.Dispose()
                    $null = $process.WaitForExit(4000)
                } catch {
                    Write-Warning "$Name did not stop gracefully: $_"
                }
            }
            if (!$process.HasExited) {
                $process.Kill()
                $process.WaitForExit()
            }
            $process.Dispose()
        }
        $http.Dispose()
    }
}

$go = (Resolve-Path -LiteralPath $GoExecutable).ProviderPath
$rust = if ($RustExecutable) { (Resolve-Path -LiteralPath $RustExecutable).ProviderPath }
if ($rust -and $go -eq $rust) { throw 'Measure two distinct executables' }

for ($attempt = 1; $attempt -le $Repeats; $attempt++) {
    if ($rust -and $attempt % 2 -eq 0) { Measure-Runtime 'Rust' $rust $attempt }
    Measure-Runtime 'Go' $go $attempt
    if ($rust -and $attempt % 2 -eq 1) { Measure-Runtime 'Rust' $rust $attempt }
}
