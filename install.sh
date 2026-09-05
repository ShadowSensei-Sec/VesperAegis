#!/bin/bash

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

cd "$PROJECT_DIR"

echo "[+] Updating package lists..."
sudo apt update

echo "[+] Installing required system packages..."
sudo apt install -y \
    python3 \
    python3-venv \
    python3-pip \
    nftables

echo "[+] Creating Python virtual environment..."

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
else
    echo "[+] Virtual environment already exists."
fi

echo "[+] Activating virtual environment..."
source .venv/bin/activate

echo "[+] Upgrading pip..."
python -m pip install --upgrade pip

echo "[+] Installing Python dependencies..."

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "[ERROR] requirements.txt not found."
    exit 1
fi

echo "[+] Creating required directories..."

mkdir -p data
mkdir -p evidence/screenshots
mkdir -p evidence/pcaps
mkdir -p evidence/test-results

echo "[+] Initializing database..."

PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/python" \
    "$PROJECT_DIR/scripts/initialize_database.py"

echo "[+] Loading default firewall rules..."

PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/python" \
    -c "from scripts.apply_rules import bootstrap_database_from_yaml; bootstrap_database_from_yaml()"

echo
echo "[+] Installation completed successfully."
echo "[+] Start the firewall with:"
echo "    ./start.sh"