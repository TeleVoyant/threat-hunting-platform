#!/usr/bin/env bash
#
# Bring up the api container with the laptop's *current* LAN IP injected as
# PUBLIC_HOST_URL, so the companion-app QR encodes a URL the phone can
# actually reach over WiFi.
#
# Re-run this whenever the laptop joins a different WiFi network.
#
# Usage:
#   ./scripts/pair-up.sh                  # default port 8000
#   API_PORT=8443 ./scripts/pair-up.sh    # override port
#
set -euo pipefail

# Always use the wireless interface (wlp*). Ignore docker0 / virbr0 / eth*
# — the phone reaches the laptop over WiFi, full stop.
WLP_IFACE=$(ip -o link show 2>/dev/null | awk -F': ' '/^[0-9]+: wlp/ {print $2; exit}')

if [ -z "${WLP_IFACE:-}" ]; then
    echo "ERROR: no wireless interface (wlp*) found." >&2
    echo "Hint: run 'ip -o link show' to list interfaces." >&2
    exit 1
fi

HOST_IP=$(ip -4 -o addr show dev "$WLP_IFACE" 2>/dev/null |
    awk '{print $4}' | cut -d/ -f1 | head -n1)

if [ -z "${HOST_IP:-}" ]; then
    echo "ERROR: ${WLP_IFACE} has no IPv4 address. Connect to WiFi first." >&2
    exit 1
fi

PORT="${API_PORT:-8000}"
export PUBLIC_HOST_URL="http://${HOST_IP}:${PORT}"

cd "$(dirname "$0")/.."

echo "WiFi iface  : ${WLP_IFACE}"
echo "Host LAN IP : ${HOST_IP}"
echo "PUBLIC_HOST_URL=${PUBLIC_HOST_URL}"
echo

docker compose up -d

cat <<EOF

Done. From your phone on the same WiFi:
  1. Open ${PUBLIC_HOST_URL}/dashboard/settings/companion (log in).
  2. Tap "Scan QR" in the APT THP app on the phone.
  3. Aim at the QR.

Or, on this laptop, open:
  ${PUBLIC_HOST_URL}/dashboard/settings/companion

EOF
