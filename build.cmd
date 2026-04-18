@echo off
setlocal
if not exist build mkdir build
call go mod tidy
if errorlevel 1 exit /b %errorlevel%
call go build -mod=mod -trimpath -ldflags="-H=windowsgui -s -w" -o build\pitchProx.exe .\cmd\pitchprox
if errorlevel 1 exit /b %errorlevel%
if exist WinDivert.dll copy /Y WinDivert.dll build\WinDivert.dll >nul
if exist WinDivert64.sys copy /Y WinDivert64.sys build\WinDivert64.sys >nul
echo Built build\pitchProx.exe (GUI subsystem, no extra conhost.exe on double click)
if not exist build\WinDivert.dll echo Missing build\WinDivert.dll. Download WinDivert 2.2.2 from https://github.com/basil00/WinDivert/releases/tag/v2.2.2
if not exist build\WinDivert64.sys echo Missing build\WinDivert64.sys. Download WinDivert 2.2.2 from https://github.com/basil00/WinDivert/releases/tag/v2.2.2
endlocal
