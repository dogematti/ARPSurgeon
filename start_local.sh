#!/bin/bash
set -e

# Resolve script directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
VENV_DIR="$DIR/.venv"

# Ensure virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Virtual environment not found. Setting up..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install -r "$DIR/requirements.txt"
    echo "[*] Setup complete."
fi

echo "[*] Starting ARPSurgeon Web Control Plane..."
echo "[*] Dashboard: http://127.0.0.1:8000/static/index.html"
echo "[!] Note: Root privileges required for raw packet operations."

# Run using the venv's python interpreter with sudo
sudo "$VENV_DIR/bin/python" -m arpsurgeon web --host 127.0.0.1 --port 8000
