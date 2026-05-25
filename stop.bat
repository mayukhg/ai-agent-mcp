@echo off
echo ======================================================================
echo Shutting down Security Sentinel GUI Web Server (Port 8000)...
echo ======================================================================

setlocal enabledelayedexpansion

:: Find PID on port 8000
set "PID="
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do (
    set "PID=%%a"
)

if defined PID (
    echo [SYSTEM] Terminating process ID !PID! running on port 8000...
    taskkill /f /pid !PID!
    echo [SYSTEM] Shutdown complete.
) else (
    echo [INFO] No active process discovered listening on port 8000.
)

pause
