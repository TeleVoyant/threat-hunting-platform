# APT Threat Hunting Platform — common ops shortcuts.
#
# `make up`    bring the stack up with the laptop's WiFi IP injected as
#              PUBLIC_HOST_URL so the companion-app QR is reachable.
# `make down`  stop everything.
# `make logs`  tail the api logs.
# `make ps`    list running services.
# `make restart-api` restart only the api with a fresh IP detect.

.PHONY: up down logs ps restart-api help wazuh-certs wazuh-reset \
        normalize-handler normalize-ps1 apk apk-debug sign-apk keystore-create

help:
	@echo "Targets:"
	@echo "  make up                - start the stack (auto-detect wlp* IP)"
	@echo "  make down              - stop the stack"
	@echo "  make restart-api       - restart api only with fresh IP"
	@echo "  make logs              - follow api logs"
	@echo "  make ps                - list running services"
	@echo "  make wazuh-certs       - (re)generate Wazuh SSL certs"
	@echo "  make wazuh-reset       - wipe Wazuh volumes + certs and bootstrap from scratch"
	@echo "  make normalize-handler - CRLF + UTF-8 BOM normalise the agent handler script"
	@echo "  make normalize-ps1     - same, for every .ps1 under scripts/"
	@echo "  make apk               - build release APK and ship to data/downloads/companion.apk"
	@echo "  make apk-debug         - same but build the debug variant (faster, larger)"
	@echo "  make keystore-create   - first-time setup: generate a release keystore (interactive)"
	@echo "  make sign-apk          - sign data/downloads/companion.apk (see ./scripts/sign_apk.sh --help)"

# Normalise the agent_command_handler.ps1 source so PS 5.1 on the endpoint
# parses it identically regardless of which editor / OS produced the bytes.
# Idempotent — running on an already-canonical file is a silent no-op.
# Run this before any commit that touches the handler script.
normalize-handler:
	@python3 scripts/normalize_ps1.py scripts/agent_command_handler.ps1

# Same, sweeping every .ps1 file in scripts/. Defensive — picks up future
# PowerShell scripts without needing to extend the Makefile.
normalize-ps1:
	@python3 scripts/normalize_ps1.py --all

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

# ---------------------------------------------------------------------------
# Companion APK build + ship.
#
# Builds the Android companion app and copies the resulting .apk to
# data/downloads/companion.apk -- which is what api/routes/downloads.py
# serves at /downloads/companion.apk and what the dashboard's "Pair phone"
# page (/dashboard/settings/companion) offers as a Download button.
#
# `make apk`        builds the RELEASE variant (signed with debug keystore
#                   per mobile/android/app/build.gradle.kts -- operators
#                   replace this with their own keystore for production).
#                   This is the variant the dashboard hint recommends.
# `make apk-debug`  builds the DEBUG variant. Faster, larger, includes the
#                   debug runtime. Use when iterating locally on the app.
#
# Both targets ensure data/downloads/ exists, then atomically replace the
# file via mv so a phone mid-download never sees a truncated file. The
# /downloads/companion.apk route picks up the new bytes immediately on the
# next request -- no api restart needed.
#
# If KEYSTORE is set, the APK is automatically signed after shipping.
#   make apk KEYSTORE=apt-thp.keystore KEY_ALIAS=apt-thp STOREPASS=secret
# ---------------------------------------------------------------------------
_APK_DEST := data/downloads/companion.apk
_GRADLE   := ./gradlew

apk:
	@echo "[apk] building release variant..."
	@cd mobile/android && $(_GRADLE) :app:assembleRelease
	@mkdir -p $(dir $(_APK_DEST))
	@SRC=$$(find mobile/android/app/build/outputs/apk/release -name 'app-release*.apk' -type f | head -1); \
	 if [ -z "$$SRC" ]; then echo "[apk] FAIL: no APK produced under mobile/android/app/build/outputs/apk/release/"; exit 1; fi; \
	 cp "$$SRC" $(_APK_DEST).new && mv -f $(_APK_DEST).new $(_APK_DEST); \
	 echo "[apk]   shipped $$SRC"; \
	 echo "[apk]      -> $(_APK_DEST)  ($$(du -h $(_APK_DEST) | cut -f1))"; \
	 echo "[apk] dashboard download: /dashboard/settings/companion"
	@if [ -n "$(KEYSTORE)" ]; then \
	   $(MAKE) sign-apk KEYSTORE="$(KEYSTORE)" KEY_ALIAS="$(KEY_ALIAS)" \
	     $(if $(PASS_FILE),PASS_FILE="$(PASS_FILE)",); \
	 fi

apk-debug:
	@echo "[apk-debug] building debug variant..."
	@cd mobile/android && $(_GRADLE) :app:assembleDebug
	@mkdir -p $(dir $(_APK_DEST))
	@SRC=$$(find mobile/android/app/build/outputs/apk/debug -name 'app-debug.apk' -type f | head -1); \
	 if [ -z "$$SRC" ]; then echo "[apk-debug] FAIL: no APK produced under mobile/android/app/build/outputs/apk/debug/"; exit 1; fi; \
	 cp "$$SRC" $(_APK_DEST).new && mv -f $(_APK_DEST).new $(_APK_DEST); \
	 echo "[apk-debug]   shipped $$SRC"; \
	 echo "[apk-debug]      -> $(_APK_DEST)  ($$(du -h $(_APK_DEST) | cut -f1))"; \
	 echo "[apk-debug] dashboard download: /dashboard/settings/companion"
	@if [ -n "$(KEYSTORE)" ]; then \
	   $(MAKE) sign-apk KEYSTORE="$(KEYSTORE)" KEY_ALIAS="$(KEY_ALIAS)" \
	     $(if $(PASS_FILE),PASS_FILE="$(PASS_FILE)",); \
	 fi

# ---------------------------------------------------------------------------
# sign-apk -- re-sign data/downloads/companion.apk with a release keystore.
#
# This is a thin Makefile wrapper around scripts/sign_apk.sh. The real
# logic (apksigner auto-detection, secure password handling via file/env/
# interactive, atomic sign+verify+swap, cert fingerprint display, refusal
# to use the broken jarsigner-only path) lives in the script.
#
# Required variables:
#   KEYSTORE   - path to the .keystore / .jks file
#   KEY_ALIAS  - key alias inside the keystore
#
# Password sources (script picks first that resolves):
#   1. PASS_FILE=path     A 2-line file (line1=storepass, line2=keypass).
#                         Best for CI -- chmod 600 the file.
#   2. STOREPASS env var  Set in env (`STOREPASS='...' make sign-apk ...`).
#                         Optional KEYPASS env var (defaults to STOREPASS).
#   3. interactive prompt If neither of the above and stdin is a TTY.
#
# Usage:
#   make sign-apk KEYSTORE=apt-thp.keystore KEY_ALIAS=apt-thp
#     (prompts for password)
#
#   STOREPASS='your-secret' \
#     make sign-apk KEYSTORE=apt-thp.keystore KEY_ALIAS=apt-thp
#     (no prompt; password from env)
#
#   make sign-apk KEYSTORE=apt-thp.keystore KEY_ALIAS=apt-thp PASS_FILE=.pw
#     (no prompt; password from .pw file)
#
# First-time setup (no keystore yet):
#   make keystore-create
# ---------------------------------------------------------------------------
sign-apk:
	@test -n "$(KEYSTORE)"  || { echo "[sign] ERROR: KEYSTORE is required (see 'make help' or scripts/sign_apk.sh --help)"; exit 1; }
	@test -n "$(KEY_ALIAS)" || { echo "[sign] ERROR: KEY_ALIAS is required"; exit 1; }
	@./scripts/sign_apk.sh \
	    --keystore "$(KEYSTORE)" \
	    --alias    "$(KEY_ALIAS)" \
	    $(if $(PASS_FILE),--pass-file "$(PASS_FILE)",)

# ---------------------------------------------------------------------------
# keystore-create -- generate a new release keystore (interactive).
#
# First-time setup helper. Wraps scripts/create_keystore.sh which itself
# wraps `keytool` (bundled with any JDK). Prompts for path, alias, CN,
# and password.
#
# Usage:
#   make keystore-create
#     (fully interactive)
#
#   make keystore-create KEYSTORE=apt-thp.keystore KEY_ALIAS=apt-thp
#     (uses provided path/alias; still prompts for password interactively
#      -- this is the SAFEST place to enter a password)
# ---------------------------------------------------------------------------
keystore-create:
	@./scripts/create_keystore.sh \
	    $(if $(KEYSTORE),--keystore "$(KEYSTORE)",) \
	    $(if $(KEY_ALIAS),--alias "$(KEY_ALIAS)",)
