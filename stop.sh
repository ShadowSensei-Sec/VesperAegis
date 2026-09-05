#!/bin/bash

PID=$(pgrep -f "uvicorn app.main:app" || true)

if [ -z "$PID" ]; then
    echo "[+] Firewall API is not running."
    exit 0
fi

echo "[+] Stopping Firewall API (PID: $PID)..."

kill $PID

echo "[+] Firewall API stopped."