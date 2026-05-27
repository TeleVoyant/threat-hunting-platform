# APT Threat Hunting Platform — common ops shortcuts.
#
# `make up`    bring the stack up with the laptop's WiFi IP injected as
#              PUBLIC_HOST_URL so the companion-app QR is reachable.
# `make down`  stop everything.
# `make logs`  tail the api logs.
# `make ps`    list running services.
# `make restart-api` restart only the api with a fresh IP detect.

.PHONY: up down logs ps restart-api help wazuh-certs wazuh-reset

help:
	@echo "Targets:"
	@echo "  make up           — start the stack (auto-detect wlp* IP)"
	@echo "  make down         — stop the stack"
	@echo "  make restart-api  — restart api only with fresh IP"
	@echo "  make logs         — follow api logs"
	@echo "  make ps           — list running services"
	@echo "  make wazuh-certs  — (re)generate Wazuh indexer/manager/dashboard SSL certs"
	@echo "  make wazuh-reset  — wipe Wazuh volumes + certs and bootstrap from scratch"

wazuh-certs:
	docker compose -f generate-indexer-certs.yml run --rm generator
	@echo "Certs written to config/wazuh_indexer_ssl_certs/"

# Wipes Wazuh-only volumes (preserves platform-data: alerts, audit, devices).
wazuh-reset:
	docker compose stop wazuh-manager wazuh-indexer wazuh-dashboard
	docker compose rm -fv wazuh-manager wazuh-indexer wazuh-dashboard
	-docker volume rm threat-hunting-platform_wazuh-data threat-hunting-platform_wazuh-etc threat-hunting-platform_wazuh-indexer-data threat-hunting-platform_wazuh-dashboard-config threat-hunting-platform_wazuh-dashboard-custom 2>/dev/null || true
	rm -rf config/wazuh_indexer_ssl_certs/*
	$(MAKE) wazuh-certs
	./scripts/pair-up.sh
	@echo "Wazuh stack reset. Dashboard at https://localhost:5601 (admin / SecretPassword) — give it ~90s."

up:
	@./scripts/pair-up.sh

restart-api:
	@./scripts/pair-up.sh

down:
	docker compose down

logs:
	docker compose logs -f api

ps:
	docker compose ps
