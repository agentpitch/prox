@echo off
setlocal
if not exist build mkdir build
call go mod tidy
if errorlevel 1 exit /b %errorlevel%
call go build -trimpath -ldflags="-H=windowsgui -s -w" -o build\pitchProx.exe .\cmd\pitchprox
if errorlevel 1 exit /b %errorlevel%
echo Built build\pitchProx.exe (GUI subsystem, no extra conhost.exe on double click)
endlocal
