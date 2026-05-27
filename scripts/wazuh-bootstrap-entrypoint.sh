#!/bin/bash
#
# APT THP — wazuh-manager entrypoint wrapper.
#
# Runs BEFORE wazuh-control. Patches ossec.conf with the two settings the
# AI ingestion pipeline depends on:
#
#   <use_password>yes</use_password>   — authd enforces the bind-mounted
#                                         registration password
#   <logall_json>yes</logall_json>     — manager writes raw events to
#                                         archives.json (the pipeline reads it)
#
# Idempotent. Survives `docker compose down -v` because the patch is reapplied
# every time the container starts — the script lives in the project tree,
# not in the wiped `wazuh-etc` volume.
#
set -e

CONF=/var/ossec/etc/ossec.conf

# Docker pre-populates an empty named volume with the image's defaults BEFORE
# starting the container, so ossec.conf already exists by the time we run.
# A short timeout guard handles the edge case where it doesn't.
for _ in 1 2 3 4 5; do
    [ -f "$CONF" ] && break
    sleep 1
done

if [ -f "$CONF" ]; then
    patched=0
    if grep -q '<use_password>no</use_password>' "$CONF"; then
        sed -i 's|<use_password>no</use_password>|<use_password>yes</use_password>|' "$CONF"
        echo "[apt-thp-bootstrap] enabled <use_password>"
        patched=1
    fi
    if grep -q '<logall_json>no</logall_json>' "$CONF"; then
        sed -i 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' "$CONF"
        echo "[apt-thp-bootstrap] enabled <logall_json>"
        patched=1
    fi
    [ "$patched" = "1" ] || echo "[apt-thp-bootstrap] ossec.conf already correct"
else
    echo "[apt-thp-bootstrap] WARN: $CONF not found; skipping patch" >&2
fi

# Hand control back to Wazuh's own init system.
exec /init "$@"
