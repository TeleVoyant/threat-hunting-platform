#!/usr/bin/env bash
# ----------------------------------------------------------------------------
#  create_keystore.sh -- generate a release keystore for signing companion.apk.
#
#  First-time setup helper. Wraps `keytool` (bundled with the JDK) with
#  sensible defaults for a self-signed Android release key.
#
#  The resulting keystore + key are RSA 4096 / SHA-256, valid for 30 years
#  (the Android Play Store accepts a minimum of 25 years for release keys --
#  go big so a key replacement is a deliberate decision, not a deadline).
#
#  USAGE
#  -----
#    ./scripts/create_keystore.sh
#      Prompts interactively for keystore path, alias, password, and CN.
#
#    ./scripts/create_keystore.sh --keystore apt-thp.keystore --alias apt-thp
#      Uses the provided path + alias; still prompts for password (interactive
#      is safer for a one-time setup than putting it in env / argv).
#
#  After generation, sign an APK with:
#    ./scripts/sign_apk.sh --keystore <path> --alias <alias>
# ----------------------------------------------------------------------------

set -euo pipefail

if [[ -t 1 ]]; then
    C_DIM='\033[2m'; C_GREEN='\033[32m'; C_RED='\033[31m'; C_OFF='\033[0m'
else
    C_DIM=''; C_GREEN=''; C_RED=''; C_OFF=''
fi
log() { echo -e "${C_DIM}[keystore]${C_OFF} $*"; }
ok()  { echo -e "${C_GREEN}[keystore]${C_OFF} $*"; }
err() { echo -e "${C_RED}[keystore]${C_OFF} ${C_RED}ERROR:${C_OFF} $*" >&2; }

KEYSTORE=""
ALIAS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keystore) KEYSTORE="$2"; shift 2 ;;
        --alias)    ALIAS="$2";    shift 2 ;;
        -h|--help)
            sed -n '2,/^# ----/p' "$0" | sed -n '/^#/p' | sed 's/^# \?//'
            exit 1 ;;
        *) err "unknown argument: $1"; exit 1 ;;
    esac
done

command -v keytool >/dev/null 2>&1 || {
    err "keytool not found -- install a JDK (Adoptium / OpenJDK)"
    exit 2
}

if [[ -z "$KEYSTORE" ]]; then
    read -rp "Keystore path [apt-thp.keystore]: " KEYSTORE
    [[ -z "$KEYSTORE" ]] && KEYSTORE="apt-thp.keystore"
fi
if [[ -e "$KEYSTORE" ]]; then
    err "refuse to overwrite existing file: $KEYSTORE"
    err "delete it first if you intend to replace it (you'll lose the old key forever)"
    exit 1
fi
if [[ -z "$ALIAS" ]]; then
    read -rp "Key alias [apt-thp]: " ALIAS
    [[ -z "$ALIAS" ]] && ALIAS="apt-thp"
fi

read -rp "Common Name (CN) [APT Threat Hunting Platform]: " CN
[[ -z "$CN" ]] && CN="APT Threat Hunting Platform"
read -rp "Organization (O) [APT THP FYP]: " ORG
[[ -z "$ORG" ]] && ORG="APT THP FYP"
read -rp "Locality (L) [Dar es Salaam]: " LOC
[[ -z "$LOC" ]] && LOC="Dar es Salaam"
read -rp "Country (C, 2-letter) [TZ]: " COUNTRY
[[ -z "$COUNTRY" ]] && COUNTRY="TZ"

echo
log "About to generate:"
log "  keystore  : $KEYSTORE"
log "  alias     : $ALIAS"
log "  algorithm : RSA 4096 + SHA256"
log "  validity  : 30 years (10950 days)"
log "  DN        : CN=$CN, O=$ORG, L=$LOC, C=$COUNTRY"
read -rp "Proceed? [y/N] " GO
[[ "$GO" =~ ^[Yy]$ ]] || { log "aborted"; exit 1; }

# keytool prompts for password interactively (safest -- never in argv/env).
keytool -genkeypair \
    -keystore "$KEYSTORE" \
    -alias "$ALIAS" \
    -keyalg RSA -keysize 4096 \
    -sigalg SHA256withRSA \
    -validity 10950 \
    -dname "CN=$CN, O=$ORG, L=$LOC, C=$COUNTRY"

chmod 600 "$KEYSTORE"
ok "keystore created: $KEYSTORE (mode 600)"
ok "alias            : $ALIAS"
ok ""
ok "BACK UP THIS FILE NOW. Losing it means you can never push an update to"
ok "anyone who installed an APK signed with this key -- Android verifies"
ok "that updates are signed by the SAME certificate as the original install."
ok ""
ok "Next: make apk && ./scripts/sign_apk.sh --keystore $KEYSTORE --alias $ALIAS"
