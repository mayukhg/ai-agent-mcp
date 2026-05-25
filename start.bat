@echo off
echo ======================================================================
echo Starting Security Sentinel GUI Web Server ^& MCP Client...
echo ======================================================================

cd /d "%~dp0"

if not exist "venv" (
    echo [SYSTEM] Creating Python virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment. Please install Python.
        pause
        exit /b 1
    )
    echo [SYSTEM] Installing project dependencies...
    call .\venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call .\venv\Scripts\activate.bat
)

echo [SYSTEM] Launching agent_backend.py...
python agent_backend.py
pause
