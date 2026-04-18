$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path build | Out-Null
go build -trimpath -ldflags='-H=windowsgui -s -w' -o build\pitchProx.exe .\cmd\pitchprox
Write-Host 'Built build\pitchProx.exe (GUI subsystem, no extra conhost.exe on double click)'
