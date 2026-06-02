#!/usr/bin/env bash
# scripts/fetch_install_cache.sh
#
# Pre-fetch the Wazuh agent MSI + Sysmon ZIP into scripts/cache/ so the
# api container can serve them from /install/wazuh-agent.msi and
# /install/sysmon.zip — endpoints then never touch the public internet.
#
# Run once per build host (or whenever you bump versions):
#   bash scripts/fetch_install_cache.sh
#
# Then `docker compose build api` picks the files up via the existing
# COPY scripts/ scripts/ directive in the Dockerfile.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="$SCRIPT_DIR/cache"
mkdir -p "$CACHE_DIR"

WAZUH_VERSION="${WAZUH_VERSION:-4.7.0}"
WAZUH_MSI="wazuh-agent-${WAZUH_VERSION}-1.msi"
WAZUH_URL="https://packages.wazuh.com/4.x/windows/${WAZUH_MSI}"

SYSMON_ZIP="Sysmon.zip"
SYSMON_URL="https://download.sysinternals.com/files/Sysmon.zip"

fetch() {
    local url="$1" dest="$2"
    if [[ -s "$dest" ]]; then
        echo "[cache] already present: $(basename "$dest")"
        return 0
    fi
    echo "[cache] downloading $(basename "$dest") from $url"
    # -L follows redirects, -f fails on 4xx/5xx, -S surfaces curl errors,
    # -s quiets progress so the log stays grep-able in CI.
    if ! curl -fLsS -o "$dest" "$url"; then
        echo "[cache] FAILED to download $url" >&2
        rm -f "$dest"
        return 1
    fi
    echo "[cache] saved: $dest ($(du -h "$dest" | cut -f1))"
}

fetch "$WAZUH_URL"  "$CACHE_DIR/$WAZUH_MSI"
fetch "$SYSMON_URL" "$CACHE_DIR/$SYSMON_ZIP"

echo
echo "Done. Cached files:"
ls -lh "$CACHE_DIR"
echo
echo "Next: docker compose build api && docker compose up -d api"
