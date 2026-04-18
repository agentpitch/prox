$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path build | Out-Null
go build -mod=mod -trimpath -ldflags='-H=windowsgui -s -w' -o build\pitchProx.exe .\cmd\pitchprox
if (Test-Path WinDivert.dll) { Copy-Item WinDivert.dll build\WinDivert.dll -Force }
if (Test-Path WinDivert64.sys) { Copy-Item WinDivert64.sys build\WinDivert64.sys -Force }
Write-Host 'Built build\pitchProx.exe (GUI subsystem, no extra conhost.exe on double click)'
if (-not (Test-Path build\WinDivert.dll)) {
    Write-Host 'Missing build\WinDivert.dll. Download WinDivert 2.2.2 from https://github.com/basil00/WinDivert/releases/tag/v2.2.2'
}
if (-not (Test-Path build\WinDivert64.sys)) {
    Write-Host 'Missing build\WinDivert64.sys. Download WinDivert 2.2.2 from https://github.com/basil00/WinDivert/releases/tag/v2.2.2'
}
