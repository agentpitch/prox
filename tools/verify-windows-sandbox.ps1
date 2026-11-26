param(
    [Parameter(Mandatory = $true)][string]$InputDirectory,
    [Parameter(Mandatory = $true)][string]$ResultPath,
    [ValidateSet('go', 'rust')][string[]]$Implementations = @('go', 'rust')
)

$ErrorActionPreference = 'Stop'
$results = [Collections.Generic.List[object]]::new()
$diagnostics = $null

function Wait-Result([scriptblock]$Probe, [int]$Seconds = 15) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $result = & $Probe
        if ($result) { return $result }
        Start-Sleep -Milliseconds 100
    } while ($clock.Elapsed.TotalSeconds -lt $Seconds)
    throw 'Timed out waiting for the isolated application'
}

function Request([string]$Base, [string]$Path, [string]$Method = 'GET', $Body = $null) {
    $params = @{ Uri = $Base + $Path; Method = $Method; TimeoutSec = 3 }
    if ($null -ne $Body) {
        $params.Body = $Body | ConvertTo-Json -Depth 12 -Compress
        $params.ContentType = 'application/json'
    }
    Invoke-RestMethod @params
}

function Socket-Request([int]$Port, [switch]$AllowBlocked) {
    $tcp = [Net.Sockets.TcpClient]::new()
    try {
        $connect = $tcp.ConnectAsync('198.51.100.42', $Port)
        if (!$connect.Wait(5000)) { throw 'No TCP response from the test route' }
        [void]$connect.GetAwaiter().GetResult()
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 5000
        $stream.WriteTimeout = 5000
        $body = [Text.Encoding]::ASCII.GetBytes("GET /sandbox-check HTTP/1.1`r`nHost: fixture.test`r`nConnection: close`r`n`r`n")
        $stream.Write($body, 0, $body.Length)
        $buffer = [byte[]]::new(4096)
        try {
            $count = $stream.Read($buffer, 0, $buffer.Length)
            [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
        } catch {
            $cause = $_.Exception
            while ($cause -and $cause -isnot [Net.Sockets.SocketException]) { $cause = $cause.InnerException }
            if (!$AllowBlocked -or !$cause -or $cause.SocketErrorCode -notin @('ConnectionReset', 'TimedOut')) { throw }
            ''
        }
    } finally {
        $tcp.Dispose()
    }
}

function Command-Exit([string]$Path, [string]$Argument, [string]$Directory) {
    $process = Start-Process -FilePath $Path -ArgumentList $Argument -WorkingDirectory $Directory -WindowStyle Hidden -PassThru
    try {
        [void]$process.Handle
        if (!$process.WaitForExit(12000)) { throw "Timed out running $Argument" }
        if ($process.ExitCode -ne 0) { throw "$Argument exited with code $($process.ExitCode)" }
    } finally {
        $process.Dispose()
    }
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The Windows Sandbox logon command is not elevated'
    }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public sealed class PitchProxSandboxProxy : IDisposable {
    private readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
    private readonly Thread worker;
    public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }
    public string RequestLine;
    public string Failure;
    public PitchProxSandboxProxy() {
        listener.Start();
        worker = new Thread(Run) { IsBackground = true };
        worker.Start();
    }
    private void Run() {
        try {
            using (var client = listener.AcceptTcpClient())
            using (var stream = client.GetStream())
            using (var reader = new StreamReader(stream, Encoding.ASCII)) {
                stream.ReadTimeout = 5000;
                RequestLine = reader.ReadLine();
                string line;
                while ((line = reader.ReadLine()) != null && line.Length != 0) { }
                Write(stream, "HTTP/1.1 200 Connection Established\r\n\r\n");
                if (reader.ReadLine() != "GET /sandbox-check HTTP/1.1")
                    throw new IOException("The forwarded HTTP request did not match");
                while ((line = reader.ReadLine()) != null && line.Length != 0) { }
                Write(stream, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nproxy");
            }
        } catch (Exception error) { Failure = error.Message; }
    }
    private static void Write(NetworkStream stream, string text) {
        var data = Encoding.ASCII.GetBytes(text);
        stream.Write(data, 0, data.Length);
    }
    public void Dispose() { listener.Stop(); worker.Join(5000); }
}
'@

    $env:PITCHPROX_DISABLE_TRAY = '1'
    foreach ($implementation in $Implementations) {
        $directory = Join-Path $env:TEMP "pitchprox-sandbox-$implementation-$([Guid]::NewGuid().ToString('N'))"
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        $files = @('pitchProx.exe')
        if ($implementation -eq 'go') { $files += @('WinDivert64.sys','WinDivert.dll') }
        foreach ($name in $files) {
            Copy-Item -LiteralPath (Join-Path $InputDirectory "$implementation/$name") -Destination (Join-Path $directory $name)
        }
        if ($implementation -eq 'rust' -and (Test-Path -LiteralPath (Join-Path $directory 'WinDivert.dll'))) {
            throw 'The Rust verification directory contains WinDivert.dll'
        }
        $path = Join-Path $directory 'pitchProx.exe'
        $configPath = Join-Path $directory 'pitchProx.config.json'
        $port = if ($implementation -eq 'go') { 18081 } else { 18082 }
        $servicePort = $port + 10
        $originalPort = $port + 30000
        $base = "http://127.0.0.1:$port"
        $cfg = @{
            version = 1; retention_minutes = 7; dropped_log_max_bytes = 10485760
            http = @{ listen = "127.0.0.1:$port" }
            transparent = @{ ipv4_listener = '0.0.0.0'; ipv6_listener = '::'; listener_port = 26001; sniff_bytes = 4096; sniff_timeout_ms = 1500 }
            proxies = @(); chains = @()
            rules = @(
                @{ id='fixture'; name='Sandbox fixture'; enabled=$true; applications='*'; target_hosts='198.51.100.42'; target_ports="$originalPort"; action='block' },
                @{ id='default'; name='Default'; enabled=$true; applications='*'; target_hosts='Any'; target_ports='Any'; action='direct' }
            )
        }
        [IO.File]::WriteAllText($configPath, ($cfg | ConvertTo-Json -Depth 12))
        $stderr = Join-Path $directory 'desktop.stderr'
        $app = Start-Process -FilePath $path -ArgumentList 'run' -WorkingDirectory $directory -WindowStyle Hidden -RedirectStandardError $stderr -PassThru
        try {
            [void]$app.Handle
            Wait-Result {
                if ($app.HasExited) { throw "Desktop exited $($app.ExitCode) $(Get-Content $stderr -Raw)" }
                try {
                    $health = Request $base '/api/health'
                    if ($health.pid -eq $app.Id) { $health }
                } catch {}
            } | Out-Null
            if ($implementation -eq 'rust') {
                $driver = Join-Path $directory 'WinDivert64.sys'
                $hash = (Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash
                if ($hash -ne '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2') {
                    throw 'Extracted driver differs from the signed upstream driver'
                }
                $results.Add(@{ implementation=$implementation; check='EXE extracts the original signed WinDivert driver'; passed=$true })
            }
            $blocked = Socket-Request $originalPort -AllowBlocked
            if ($blocked) { throw 'Blocked connection unexpectedly returned content' }
            $drop = Wait-Result {
                (Request $base '/api/dropped?q=fixture.test').items | Where-Object { $_.rule_id -eq 'fixture' } | Select-Object -First 1
            }
            if ($drop.pid -ne $PID -or $drop.original_port -ne $originalPort -or $drop.state -ne 'blocked') {
                throw 'Blocked connection did not have the expected owner and destination'
            }
            $results.Add(@{ implementation=$implementation; check='WinDivert block and owner resolution'; passed=$true })

            $proxy = [PitchProxSandboxProxy]::new()
            try {
                $cfg = Request $base '/api/config'
                $cfg.proxies = @(@{ id='local-proxy'; name='Local proxy'; type='http'; address="127.0.0.1:$($proxy.Port)"; enabled=$true })
                $cfg.rules[0].action = 'proxy'
                $cfg.rules[0] | Add-Member -NotePropertyName proxy_id -NotePropertyValue 'local-proxy'
                Request $base '/api/config' 'PUT' $cfg | Out-Null
                $reply = Socket-Request $originalPort
                if (!$reply.Contains('HTTP/1.1 200 OK') -or $proxy.RequestLine -ne "CONNECT fixture.test:$originalPort HTTP/1.1" -or $proxy.Failure) {
                    throw "Transparent HTTP proxy verification failed. Request: $($proxy.RequestLine) Error: $($proxy.Failure)"
                }
                $results.Add(@{ implementation=$implementation; check='WinDivert transparent HTTP CONNECT and relay'; passed=$true })
            } finally {
                $proxy.Dispose()
            }
            Request $base '/api/control/stop' 'POST' | Out-Null
            if (!$app.WaitForExit(25000)) { throw 'Desktop did not exit after the stop request' }
            if ($app.ExitCode -ne 0) { throw "Desktop exit code $($app.ExitCode). $(Get-Content $stderr -Raw)" }
        } catch {
            $diagnostics = @{ implementation = $implementation }
            if (Test-Path -LiteralPath $stderr) { $diagnostics.stderr = Get-Content -LiteralPath $stderr -Raw }
            try { $diagnostics.snapshot = Request $base '/api/snapshot?include_logs=1' } catch {}
            throw
        } finally {
            if (!$app.HasExited) { $app.Kill(); $app.WaitForExit() }
            $app.Dispose()
        }
        $cfg.rules = @($cfg.rules[1])
        $cfg.http.listen = "127.0.0.1:$servicePort"
        [IO.File]::WriteAllText($configPath, ($cfg | ConvertTo-Json -Depth 12))
        Command-Exit $path 'install' $directory
        try {
            Command-Exit $path 'start' $directory
            Wait-Result {
                try { Request "http://127.0.0.1:$servicePort" '/api/health' } catch {}
            } | Out-Null
            Command-Exit $path 'stop' $directory
            Wait-Result { if ((Get-Service pitchProx).Status -eq 'Stopped') { $true } } | Out-Null
            $results.Add(@{ implementation=$implementation; check='install, start, HTTP control, stop and uninstall under SCM'; passed=$true })
        } finally {
            if ((Get-Service pitchProx -ErrorAction SilentlyContinue).Status -eq 'Running') {
                Command-Exit $path 'stop' $directory
                Wait-Result { if ((Get-Service pitchProx).Status -eq 'Stopped') { $true } } | Out-Null
            }
            Command-Exit $path 'uninstall' $directory
        }
    }
    $report = @{ ok = $true; checks = @($results.ToArray()) }
} catch {
    $report = @{ ok = $false; checks = @($results.ToArray()); error = $_.Exception.Message; stack = $_.ScriptStackTrace; diagnostics = $diagnostics }
} finally {
    [IO.File]::WriteAllText($ResultPath, ($report | ConvertTo-Json -Depth 8))
}
