#!/bin/bash
echo "======================================================================"
echo "Starting Security Sentinel GUI Web Server & MCP Client..."
echo "======================================================================"

# Navigate to script directory
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "[SYSTEM] Creating Python virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create virtual environment. Please install python3-venv."
        exit 1
    fi
    echo "[SYSTEM] Installing project dependencies..."
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

echo "[SYSTEM] Launching agent_backend.py..."
python agent_backend.py
