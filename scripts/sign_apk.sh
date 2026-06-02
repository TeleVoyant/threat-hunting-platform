#!/usr/bin/env bash
# ----------------------------------------------------------------------------
#  sign_apk.sh -- re-sign data/downloads/companion.apk with a release keystore.
#
#  Why a shell script and not Makefile: signing has too many failure modes
#  (missing tool, bad keystore, wrong password, unaligned APK, signature
#  verify failure) to express cleanly inside Makefile recipe backslash-soup.
#  This script does ONE thing well, and `make sign-apk` wraps it.
#
#  REQUIREMENTS
#  ------------
#  - apksigner from the Android SDK build-tools 24.0.3 or newer.
#    Auto-detected in: PATH, $ANDROID_HOME/build-tools/*/apksigner,
#    $ANDROID_SDK_ROOT/build-tools/*/apksigner. Newest build-tools version
#    found wins.
#  - The unsigned-or-debug-signed APK at data/downloads/companion.apk
#    (produced by `make apk`).
#  - A keystore file -- generate one with scripts/create_keystore.sh if you
#    don't have one yet.
#
#  WHY NOT jarsigner: Android 9+ (API 28+) refuses APKs that carry ONLY a
#  v1 (JAR) signature with INSTALL_PARSE_FAILED_NO_CERTIFICATES. jarsigner
#  cannot produce the v2/v3 schemes that modern Android requires. apksigner
#  produces all three by default. This script will not try jarsigner.
#
#  PASSWORD SOURCES (checked in order, first that resolves wins)
#  -------------------------------------------------------------
#    1. --pass-file PATH       Read from a file (newline-stripped). Best for
#                              CI/automation: no env, no argv, no history.
#    2. STOREPASS env var      Read from the environment. Good for
#                              interactive use: invisible to `ps` (apksigner
#                              reads it via env:VAR).
#    3. interactive prompt     Falls back to a read -s prompt on a TTY.
#    4. (refuses to use --storepass on argv -- exposes via ps)
#
#  USAGE
#  -----
#    # Best: passwords in a file (chmod 600)
#    ./scripts/sign_apk.sh --keystore apt-thp.keystore --alias apt-thp \
#                          --pass-file .keystore.pass
#
#    # Good: passwords in env
#    STOREPASS='secret' KEYPASS='secret' \
#      ./scripts/sign_apk.sh --keystore apt-thp.keystore --alias apt-thp
#
#    # Interactive (handy for one-off):
#    ./scripts/sign_apk.sh --keystore apt-thp.keystore --alias apt-thp
#
#  EXIT CODES
#  ----------
#    0   success (APK signed, verified, swapped in atomically)
#    1   usage / missing-arg
#    2   apksigner not found
#    3   keystore / APK file missing
#    4   signing or verification failed (original APK untouched)
# ----------------------------------------------------------------------------

set -euo pipefail

# Resolve repo root so we work from anywhere on the filesystem.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APK_PATH="$REPO_ROOT/data/downloads/companion.apk"

# Colors for human-readable output (no-op when not a TTY).
if [[ -t 1 ]]; then
    C_RED='\033[31m'; C_YELLOW='\033[33m'; C_GREEN='\033[32m'
    C_DIM='\033[2m'; C_BOLD='\033[1m'; C_OFF='\033[0m'
else
    C_RED=''; C_YELLOW=''; C_GREEN=''; C_DIM=''; C_BOLD=''; C_OFF=''
fi

log()  { echo -e "${C_DIM}[sign]${C_OFF} $*"; }
ok()   { echo -e "${C_GREEN}[sign]${C_OFF} $*"; }
warn() { echo -e "${C_YELLOW}[sign]${C_OFF} ${C_YELLOW}$*${C_OFF}"; }
err()  { echo -e "${C_RED}[sign]${C_OFF} ${C_RED}ERROR:${C_OFF} $*" >&2; }

usage() {
    sed -n '2,/^# ----/p' "$0" | sed -n '/^#/p' | sed 's/^# \?//' | head -90
    exit 1
}

# -------------------------------- arg parse ---------------------------------
KEYSTORE=""
ALIAS=""
PASS_FILE=""
APK_OVERRIDE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keystore)   KEYSTORE="$2";     shift 2 ;;
        --alias)      ALIAS="$2";        shift 2 ;;
        --pass-file)  PASS_FILE="$2";    shift 2 ;;
        --apk)        APK_OVERRIDE="$2"; shift 2 ;;
        -h|--help)    usage ;;
        *) err "unknown argument: $1"; usage ;;
    esac
done

[[ -n "$APK_OVERRIDE" ]] && APK_PATH="$APK_OVERRIDE"

# -------------------------------- validate ----------------------------------
if [[ -z "$KEYSTORE" || -z "$ALIAS" ]]; then
    err "--keystore and --alias are required"
    usage
fi
if [[ ! -f "$KEYSTORE" ]]; then
    err "keystore not found: $KEYSTORE"
    err "create one with: ./scripts/create_keystore.sh"
    exit 3
fi
if [[ ! -f "$APK_PATH" ]]; then
    err "APK not found: $APK_PATH"
    err "build one with: make apk"
    exit 3
fi

# ----------------------- apksigner auto-detection ---------------------------
find_apksigner() {
    if command -v apksigner >/dev/null 2>&1; then
        command -v apksigner
        return 0
    fi
    local roots=("${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}")
    for root in "${roots[@]}"; do
        [[ -z "$root" || ! -d "$root/build-tools" ]] && continue
        # Sort by version (lexicographic on dotted versions = newest last)
        local newest
        newest="$(find "$root/build-tools" -maxdepth 2 -name apksigner -type f \
                  2>/dev/null | sort -V | tail -1)"
        if [[ -n "$newest" && -x "$newest" ]]; then
            echo "$newest"
            return 0
        fi
    done
    return 1
}

APKSIGNER="$(find_apksigner)" || {
    err "apksigner not found."
    err "Install Android SDK build-tools and ensure one of these is set:"
    err "  - apksigner on PATH"
    err "  - \$ANDROID_HOME (currently: ${ANDROID_HOME:-unset})"
    err "  - \$ANDROID_SDK_ROOT (currently: ${ANDROID_SDK_ROOT:-unset})"
    exit 2
}
log "using $APKSIGNER"

# ----------------------- password resolution --------------------------------
# We need TWO passwords: storepass (keystore) + keypass (the key inside).
# Most setups use the same value for both, so KEYPASS defaults to STOREPASS.
#
# Resolved values are written to a tempfile that apksigner reads via
# --ks-pass file:... -- this avoids both `ps` exposure and env-var exposure
# via /proc/self/environ to other processes of the same user.

resolve_passwords() {
    local sp="" kp=""
    if [[ -n "$PASS_FILE" ]]; then
        [[ -f "$PASS_FILE" ]] || { err "pass-file not found: $PASS_FILE"; exit 3; }
        sp="$(head -n 1 "$PASS_FILE" | tr -d '\r\n')"
        kp="$(sed -n '2p' "$PASS_FILE" | tr -d '\r\n')"
        [[ -z "$kp" ]] && kp="$sp"
        log "passwords sourced from --pass-file"
    elif [[ -n "${STOREPASS:-}" ]]; then
        sp="$STOREPASS"
        kp="${KEYPASS:-$STOREPASS}"
        log "passwords sourced from STOREPASS / KEYPASS env"
    elif [[ -t 0 ]]; then
        echo -n "Enter keystore password: " >&2
        read -rs sp; echo >&2
        echo -n "Enter key password (blank = same as keystore): " >&2
        read -rs kp; echo >&2
        [[ -z "$kp" ]] && kp="$sp"
        log "passwords sourced from interactive prompt"
    else
        err "no password source: pass --pass-file PATH, set STOREPASS env,"
        err "or run interactively (stdin is not a TTY)"
        exit 1
    fi
    [[ -n "$sp" ]] || { err "keystore password is empty"; exit 1; }
    STOREPASS_VAL="$sp"
    KEYPASS_VAL="$kp"
}

resolve_passwords

# Write passwords to two pipe-readable tempfiles. apksigner accepts
# pass:LITERAL (insecure) / env:VARNAME (better) / file:PATH (best).
# The tempfile lives only in /tmp and is shredded on exit.
PASSDIR="$(mktemp -d -t apk-sign-XXXXXX)"
chmod 700 "$PASSDIR"
SP_FILE="$PASSDIR/sp"; KP_FILE="$PASSDIR/kp"
printf '%s' "$STOREPASS_VAL" > "$SP_FILE"
printf '%s' "$KEYPASS_VAL"   > "$KP_FILE"
chmod 600 "$SP_FILE" "$KP_FILE"
unset STOREPASS_VAL KEYPASS_VAL

cleanup() {
    [[ -d "$PASSDIR" ]] && { shred -u "$PASSDIR"/* 2>/dev/null || rm -f "$PASSDIR"/*; rmdir "$PASSDIR"; }
    [[ -f "$APK_PATH.signing" ]] && rm -f "$APK_PATH.signing"
}
trap cleanup EXIT

# ----------------------- sign + verify + swap -------------------------------
TMP="$APK_PATH.signing"

log "signing $APK_PATH"
log "  keystore : $KEYSTORE"
log "  alias    : $ALIAS"
log "  schemes  : v1+v2+v3"

# v4 disabled: requires zipalign --apksigner-friendly + extra .idsig file
# that the dashboard download flow doesn't currently serve. Re-enable when
# we add .idsig serving to api/routes/downloads.py.
if ! "$APKSIGNER" sign \
        --ks "$KEYSTORE" \
        --ks-key-alias "$ALIAS" \
        --ks-pass "file:$SP_FILE" \
        --key-pass "file:$KP_FILE" \
        --v1-signing-enabled true \
        --v2-signing-enabled true \
        --v3-signing-enabled true \
        --v4-signing-enabled false \
        --out "$TMP" "$APK_PATH"; then
    err "apksigner sign failed -- original APK at $APK_PATH untouched"
    exit 4
fi

log "verifying..."
if ! "$APKSIGNER" verify --verbose --print-certs "$TMP" >/tmp/apksigner-verify.$$ 2>&1; then
    err "apksigner verify failed -- original APK at $APK_PATH untouched"
    cat /tmp/apksigner-verify.$$ >&2
    rm -f /tmp/apksigner-verify.$$
    exit 4
fi

# Pull the SHA-256 fingerprint of the signing cert so the operator can
# pin it -- and so a future re-sign with a DIFFERENT keystore is loud and
# visible in the build output.
FINGERPRINT="$(grep -E '^Signer #1 certificate SHA-256 digest:' /tmp/apksigner-verify.$$ \
               | awk '{print $NF}' || true)"
SCHEMES="$(grep -E '^Verified using v[1-4] scheme' /tmp/apksigner-verify.$$ \
           | sed -E 's/^Verified using (v[1-4]).*$/\1/' | tr '\n' '+' | sed 's/+$//')"
rm -f /tmp/apksigner-verify.$$

# Atomic swap. mv on the same filesystem is atomic; a phone mid-download
# from /downloads/companion.apk never sees a truncated file.
mv -f "$TMP" "$APK_PATH"

SIZE="$(du -h "$APK_PATH" | cut -f1)"
ok "signed   -> $APK_PATH ($SIZE)"
ok "schemes  : ${SCHEMES:-unknown}"
[[ -n "$FINGERPRINT" ]] && ok "cert SHA-256 : $FINGERPRINT"
ok "done."
