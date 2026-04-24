#!/usr/bin/env bash
# Double-click this file to set up and launch Sonic.
# Everything happens automatically — just enter your password once.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║          Sonic — Network to Music                ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

# ── Python ────────────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "  ✗ Python 3 not found. Install from https://python.org then re-run."
  read -r -p "  Press Enter to close…"; exit 1
fi
echo "  ✓ Python: $(python3 --version)"

# ── pip deps ──────────────────────────────────────────────────────────────────
echo "  ● Installing Python dependencies…"
python3 -m pip install -q -r requirements.txt
echo "  ✓ Dependencies ready."

# ── Compile C binary ──────────────────────────────────────────────────────────
if [[ ! -x "$SCRIPT_DIR/packet_processor" ]]; then
  echo "  ● Compiling packet processor (C + libpcap)…"
  if command -v make &>/dev/null; then
    make -C "$SCRIPT_DIR"
    echo "  ✓ Compiled."
  else
    echo "  ✗ 'make' not found. Run:  xcode-select --install"
    read -r -p "  Press Enter to close…"; exit 1
  fi
fi

# ── One-time privilege setup ──────────────────────────────────────────────────
BINARY="$SCRIPT_DIR/packet_processor"
if [[ ! -u "$BINARY" ]]; then
  echo ""
  echo "  ┌────────────────────────────────────────────────────────────────┐"
  echo "  │  One-time setup: enter your macOS password to allow Sonic      │"
  echo "  │  to capture network packets.  This only happens once.          │"
  echo "  └────────────────────────────────────────────────────────────────┘"
  echo ""
  if sudo chown root:wheel "$BINARY" && sudo chmod u+s "$BINARY"; then
    echo "  ✓ Setup complete — won't be asked again."
  else
    echo "  ⚠  Setup skipped — you'll be prompted when clicking Start."
  fi
  echo ""
fi

# ── Launch ────────────────────────────────────────────────────────────────────
echo "  ┌────────────────────────────────────────────────────────────────┐"
echo "  │  Open your browser →  http://localhost:8080                    │"
echo "  │  Press Ctrl-C in this window to stop.                          │"
echo "  └────────────────────────────────────────────────────────────────┘"
echo ""
(sleep 2 && open "http://localhost:8080") &
python3 sonic_server.py
