#!/bin/bash

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

cd "$PROJECT_DIR"

if [ ! -d ".venv" ]; then
    echo "[ERROR] Python virtual environment not found."
    echo "Run ./install.sh first."
    exit 1
fi

echo "[+] Initializing firewall..."

sudo PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/python" \
    "$PROJECT_DIR/scripts/apply_rules.py"

echo "[+] Firewall initialized successfully."

echo "[+] Starting Firewall API..."

exec sudo env PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/uvicorn" \
    app.main:app \
    --host 0.0.0.0 \
    --port 8000



#exec sudo "$PROJECT_DIR/.venv/bin/uvicorn" \
   # app.main:app \
    #--host 0.0.0.0 \
   # --port 8000