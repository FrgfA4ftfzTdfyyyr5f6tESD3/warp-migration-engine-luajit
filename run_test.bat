@echo off
setlocal
:: Auto-elevate to Administrator if needed
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges for WinDivert...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo Starting Warp Migration Engine (LuaJIT 2.1 + FFI)...
luajit.exe client.lua
echo.
echo Engine exited. Check telemetry.json for diagnostic flight logs.
pause
