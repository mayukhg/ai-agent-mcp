#!/bin/bash
echo "======================================================================"
echo "Shutting down Security Sentinel GUI Web Server (Port 8000)..."
echo "======================================================================"

# Find PID on port 8000
PID=$(lsof -t -i:8000)

if [ -n "$PID" ]; then
    echo "[SYSTEM] Terminating process ID $PID running on port 8000..."
    kill -9 $PID
    echo "[SYSTEM] Shutdown complete."
else
    echo "[INFO] No active process discovered listening on port 8000."
fi
