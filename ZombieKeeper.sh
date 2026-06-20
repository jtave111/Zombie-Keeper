#!/bin/bash
# ZombieKeeper — thin wrapper → delegates to launcher.py
set -e
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if ! command -v python3 &>/dev/null; then
    echo "[-] python3 not found. Install Python 3.10+." >&2
    exit 1
fi

if ! python3 -c "from rich.console import Console" 2>/dev/null; then
    echo "[*] Installing rich..."
    pip install rich --break-system-packages -q 2>/dev/null || pip install rich -q
fi

exec python3 "$DIR/launcher.py" "$@"
