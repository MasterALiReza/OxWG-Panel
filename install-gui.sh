#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f "app.py" ]]; then
  echo "Run from project root (where app.py exists)."
  exit 1
fi

sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip

python3 -m venv .installer-venv
.installer-venv/bin/pip install --upgrade pip wheel
.installer-venv/bin/pip install flask cryptography

# Default: localhost only (no auth on this UI — use SSH tunnel or firewall)
# To allow remote access: INSTALLER_BIND=0.0.0.0 bash install-gui.sh
export INSTALLER_BIND="${INSTALLER_BIND:-127.0.0.1}"
export INSTALLER_PORT="${INSTALLER_PORT:-8888}"

if [ "$INSTALLER_BIND" != "127.0.0.1" ] && [ "$INSTALLER_BIND" != "localhost" ]; then
  echo ""
  echo "  ⚠  WARNING: INSTALLER_BIND=${INSTALLER_BIND}"
  echo "     The installer has NO authentication."
  echo "     Make sure port ${INSTALLER_PORT} is firewalled or use an SSH tunnel."
  echo ""
fi

echo "Open:"
echo "  http://${INSTALLER_BIND}:${INSTALLER_PORT}"

exec sudo -E .installer-venv/bin/python installer/installer_web.py

