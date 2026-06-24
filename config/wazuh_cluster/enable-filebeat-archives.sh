#!/bin/sh
# APT-THP: enable filebeat's "archives" input.
#
# Ships the FULL Wazuh event stream (every event, not just rule-matched alerts)
# to the indexer as wazuh-archives-4.x-*. The detection pipeline consumes
# auth/process/network/dns events that never trip a Wazuh rule, so it needs
# archives, not just alerts.
#
# Mounted into /etc/cont-init.d/ so s6-overlay runs it during container init.
# It must run AFTER 1-config-filebeat (which generates filebeat.yml from the
# INDEXER_* env vars) and BEFORE the filebeat service starts -- s6-overlay runs
# all cont-init.d scripts to completion before any services.d service, so a
# "99-" prefix on the mount target guarantees both. filebeat then reads
# archives:true on its FIRST start: no restart needed, which matters because
# bouncing filebeat makes its s6 finish script halt the whole manager container.
#
# Idempotent. No `set -e`: a non-zero exit here would abort container startup.
FB=/etc/filebeat/filebeat.yml
if [ -f "$FB" ]; then
    # Flip the `enabled:` line immediately under `archives:` to true.
    sed -i '/^[[:space:]]*archives:/{n;s/enabled:[[:space:]]*false/enabled: true/}' "$FB"
    echo "[apt-thp] filebeat archives input enabled"
else
    echo "[apt-thp] WARN: $FB not found during cont-init; archives NOT enabled" >&2
fi
exit 0
