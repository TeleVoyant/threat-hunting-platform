#!/usr/bin/env python3
"""
genesis.py — first-install configuration for the APT Threat Hunting Platform.

Configures the security parameters, operator users, and platform settings a fresh
organization needs before its first boot: generates strong secrets, creates users
(API-key auth), and writes everything to the files the backend actually reads —
config/security.yml, .env, secrets/*.txt, and (for structural values) config/*.yml.

USAGE (run from the platform root, with the venv active or via venv/bin/python):

    ./scripts/genesis.py                      # interactive, full wizard
    ./scripts/genesis.py --section users      # (re)configure just one section
    ./scripts/genesis.py --list               # show every configurable setting + caveat
    ./scripts/genesis.py --answers ans.yml --non-interactive   # automated / repeatable
    ./scripts/genesis.py --write-answers ans.yml               # save choices for re-use

SAFE BY DEFAULT:
  * refuses to clobber an already-configured install unless --force
  * backs up every file before writing (<file>.bak.<timestamp>)
  * secret files + .env + security.yml are chmod 0600

EXTENDING IT (add any future configurable platform value):
  Append a Setting(...) to the relevant section in SECTIONS below. A setting
  declares where it is written (Env / SecretFile / Yaml-path) and its caveat;
  the engine prompts for it and writes it. No other code changes needed.
"""

import argparse
import getpass
import hashlib
import os
import re
import secrets as _secrets
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

try:
    from cryptography.fernet import Fernet
except Exception:                                    # pragma: no cover
    Fernet = None

ROOT = Path(os.environ.get("GENESIS_ROOT") or Path(__file__).resolve().parent.parent)
VALID_ROLES = ("viewer", "analyst", "operator", "admin")


# ── secret generators ───────────────────────────────────────────────────────

def gen_hex(nbytes: int = 48) -> str:
    return _secrets.token_hex(nbytes)


def gen_urlsafe(nbytes: int = 32) -> str:
    return _secrets.token_urlsafe(nbytes)


def gen_fernet() -> str:
    if Fernet is None:
        raise RuntimeError("cryptography not installed — cannot generate a Fernet key")
    return Fernet.generate_key().decode()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


GENERATORS: dict[str, Callable[[], str]] = {
    "hex": lambda: gen_hex(48),         # ~96 hex chars — JWT / signing keys
    "urlsafe": lambda: gen_urlsafe(32),
    "fernet": gen_fernet,
}


# ── write targets ───────────────────────────────────────────────────────────
# A Setting declares one or more of these; the engine routes the value to each.

@dataclass
class Env:
    name: str                                       # KEY in .env


@dataclass
class SecretFile:
    filename: str                                   # secrets/<filename>


@dataclass
class Yaml:
    file: str                                       # config/<file>.yml (relative to root)
    path: str                                       # dotted path, e.g. authentication.token_expiry_hours


@dataclass
class Setting:
    name: str                                       # answers-file key / id
    label: str
    targets: list
    kind: str = "text"                              # text|secret|int|bool|choice|multiline
    default: Any = None
    generate: Optional[str] = None                  # 'hex'|'urlsafe'|'fernet'
    choices: Optional[list] = None
    caveat: str = ""
    optional: bool = False                          # blank input -> skip writing


# ════════════════════════════════════════════════════════════════════════════
#  THE CONFIGURABLE SURFACE — every setting genesis can write. Extend freely.
# ════════════════════════════════════════════════════════════════════════════

SECTIONS: dict[str, list[Setting]] = {
    "secrets": [
        Setting("JWT_SECRET", "Dashboard/API JWT signing secret",
                [Env("JWT_SECRET"), SecretFile("jwt_secret.txt")],
                kind="secret", generate="hex",
                caveat="Rotating it invalidates every logged-in session + issued token. "
                       "security.yml references it as ${JWT_SECRET}; the real value lives only here."),
        Setting("MODEL_SIGNING_KEY", "Model integrity (HMAC) signing key",
                [Env("MODEL_SIGNING_KEY"), SecretFile("model_signing_key.txt")],
                kind="secret", generate="hex",
                caveat="Detectors verify model manifests with this. Rotating it WITHOUT re-signing "
                       "existing models makes every detector refuse to load (dark detection). Retrain "
                       "or re-sign after rotating."),
        Setting("FL_LOCAL_FERNET_KEY", "Federated-learning local encryption key (Fernet)",
                [Env("FL_LOCAL_FERNET_KEY")],
                kind="secret", generate="fernet",
                caveat="Encrypts this org's FL private key + coordinator API key at rest. Rotating it "
                       "makes the existing FL keypair/api-key undecryptable — you'd re-enroll with the coordinator."),
        Setting("WAZUH_API_PASSWORD", "Wazuh Manager API password",
                [Env("WAZUH_API_PASSWORD"), SecretFile("wazuh_api_password.txt")],
                kind="secret", generate="urlsafe",
                caveat="Must match the password configured in the Wazuh stack (docker-compose / wazuh.yaml). "
                       "Set the SAME value on both sides."),
        Setting("WAZUH_REGISTRATION_PASSWORD", "Wazuh agent registration password",
                [Env("WAZUH_REGISTRATION_PASSWORD"), SecretFile("wazuh_registration_password.txt")],
                kind="secret", generate="urlsafe",
                caveat="Endpoints use it to enroll with the manager (deploy_endpoint.ps1). Distribute it "
                       "to the laptops you onboard."),
    ],
    "auth": [
        Setting("token_expiry_hours", "Dashboard session length (hours)",
                [Yaml("security.yml", "authentication.token_expiry_hours")],
                kind="int", default=8,
                caveat="Longer = fewer logins but a stolen token is valid longer."),
        Setting("rate_enabled", "Enable API rate limiting",
                [Yaml("security.yml", "rate_limiting.enabled")], kind="bool", default=True,
                caveat="Off removes brute-force / abuse protection on the API."),
        Setting("rate_rpm", "Rate limit — requests per minute",
                [Yaml("security.yml", "rate_limiting.requests_per_minute")], kind="int", default=60),
        Setting("rate_burst", "Rate limit — burst allowance",
                [Yaml("security.yml", "rate_limiting.burst")], kind="int", default=10),
    ],
    "anonymization": [
        Setting("APT_ANONYMIZE", "Pseudonymize usernames/paths during ingestion (FR-01)",
                [Env("APT_ANONYMIZE")], kind="bool", default=True,
                caveat="MUST match the value models were TRAINED with. A mismatch makes the model store "
                       "refuse to load detectors (anonymizer-mismatch SecurityError). Set once, keep stable."),
    ],
    "platform": [
        Setting("LOG_LEVEL", "Log level", [Env("LOG_LEVEL")],
                kind="choice", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO"),
        Setting("DETECTION_LOOP_ENABLED", "Run the detection loop (off = API-only)",
                [Env("DETECTION_LOOP_ENABLED")], kind="bool", default=True),
        Setting("poll_interval_seconds", "Wazuh poll interval (seconds)",
                [Yaml("platform.yml", "platform.poll_interval_seconds")],
                kind="int", default=120, optional=True,
                caveat="Structural value in platform.yml; edited in place (comments preserved)."),
        Setting("event_window_minutes", "Detection analysis window (minutes)",
                [Yaml("platform.yml", "platform.event_window_minutes")],
                kind="int", default=5, optional=True),
        Setting("alert_min_confidence", "Minimum confidence to raise an alert",
                [Yaml("platform.yml", "alerts.min_confidence")],
                kind="text", default=0.5, optional=True),
    ],
    "fl": [
        Setting("FL_PARTICIPATION_ENABLED", "Enable federated participation poller",
                [Env("FL_PARTICIPATION_ENABLED")], kind="bool", default=True),
        Setting("FL_GLOBAL_MODEL_VERIFY_HOURS", "Global-model soak before auto hot-reload (hours)",
                [Env("FL_GLOBAL_MODEL_VERIFY_HOURS")], kind="int", default=24,
                caveat="A fetched federated model auto-promotes to the live detector after this window "
                       "unless an admin promotes/rejects it first."),
    ],
    "misp": [
        Setting("MISP_ENABLED", "Enable MISP IoC enrichment", [Env("MISP_ENABLED")],
                kind="bool", default=False),
        Setting("MISP_MODE", "MISP mode (file = bundled IoCs; live = MISP server)",
                [Env("MISP_MODE")], kind="choice", choices=["file", "live"], default="file", optional=True),
        Setting("MISP_URL", "MISP server URL", [Env("MISP_URL")], kind="text", optional=True),
        Setting("MISP_API_KEY", "MISP API key", [Env("MISP_API_KEY")], kind="secret",
                optional=True, caveat="Only needed for live mode."),
    ],
    "sms": [
        Setting("BEEM_API_KEY", "Beem Africa SMS API key", [Env("BEEM_API_KEY")],
                kind="secret", optional=True,
                caveat="Leave blank to disable the SMS channel."),
        Setting("BEEM_SECRET_KEY", "Beem secret key", [Env("BEEM_SECRET_KEY")],
                kind="secret", optional=True),
        Setting("BEEM_SENDER_ID", "Beem sender ID (pre-registered)", [Env("BEEM_SENDER_ID")],
                kind="text", default="APT-THP", optional=True),
    ],
    "smtp": [
        Setting("SMTP_HOST", "SMTP relay host (in-country only — data sovereignty)",
                [Env("SMTP_HOST")], kind="text", optional=True),
        Setting("SMTP_PORT", "SMTP port", [Env("SMTP_PORT")], kind="int", default=587, optional=True),
        Setting("SMTP_USERNAME", "SMTP username", [Env("SMTP_USERNAME")], kind="text", optional=True),
        Setting("SMTP_PASSWORD", "SMTP password", [Env("SMTP_PASSWORD")], kind="secret", optional=True),
    ],
    "retrain": [
        Setting("RETRAIN_ENABLED", "Enable the auto-retrain scheduler", [Env("RETRAIN_ENABLED")],
                kind="bool", default=False,
                caveat="Memory-heavy; new models are STAGED (need admin promotion), not auto-live."),
        Setting("RETRAIN_INTERVAL_SECONDS", "Retrain cadence (seconds)",
                [Env("RETRAIN_INTERVAL_SECONDS")], kind="int", default=86400, optional=True),
    ],
}

# Order is the prompt sequence (writes are collected then applied atomically at
# the end, so this order is for UX, not correctness): foundational identity &
# secrets first, then platform/privacy, then optional features.
SECTION_ORDER = ["secrets", "users", "auth", "platform", "anonymization",
                 "fl", "misp", "sms", "smtp", "retrain"]
SECTION_TITLES = {
    "secrets": "Secrets & keys", "auth": "Authentication", "users": "Operator users",
    "anonymization": "Privacy / anonymization", "platform": "Platform basics",
    "fl": "Federated learning", "misp": "Threat intel (MISP)", "sms": "SMS alerts (Beem)",
    "smtp": "Email alerts (SMTP)", "retrain": "Auto-retrain",
}


# ── terminal helpers ─────────────────────────────────────────────────────────

class C:
    B = "\033[1m"; DIM = "\033[2m"; G = "\033[32m"; Y = "\033[33m"; R = "\033[31m"
    CY = "\033[36m"; X = "\033[0m"


def hr(title=""):
    print(f"\n{C.B}{C.CY}── {title} {'─' * max(2, 60 - len(title))}{C.X}")


def caveat(text):
    if text:
        print(f"  {C.Y}⚠ {text}{C.X}")


# ── value prompting ──────────────────────────────────────────────────────────

class Prompter:
    def __init__(self, answers: dict, interactive: bool):
        self.answers = answers
        self.interactive = interactive

    def value_for(self, s: Setting):
        """Resolve a setting's value: answers-file first, then prompt (interactive),
        else default / auto-generate. Returns (value, write?) — write False => skip."""
        provided = self.answers.get(s.name, None)

        # Non-interactive: answers -> generate(secret) -> default -> skip
        if not self.interactive:
            if provided is not None and provided != "":
                return self._coerce(s, provided), True
            if s.generate:
                return GENERATORS[s.generate](), True
            if s.default is not None:
                return s.default, True
            return None, False                           # nothing to write -> skip

        # Interactive
        print(f"\n{C.B}{s.label}{C.X}")
        caveat(s.caveat)
        if s.kind == "secret":
            return self._prompt_secret(s, provided)
        if s.kind == "bool":
            return self._prompt_bool(s, provided), True
        if s.kind == "int":
            return self._prompt_int(s, provided), True
        if s.kind == "choice":
            return self._prompt_choice(s, provided), True
        return self._prompt_text(s, provided)

    def _coerce(self, s, v):
        if s.kind == "bool":
            return v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")
        if s.kind == "int":
            return int(v)
        return v

    def _prompt_secret(self, s, provided):
        hint = "[Enter = generate, or type a custom value" + \
               (", 'skip' to leave unset" if s.optional else "") + "]"
        raw = input(f"  value {C.DIM}{hint}{C.X}: ").strip()
        if raw == "" :
            if provided is not None:
                return str(provided), True
            if s.generate:
                v = GENERATORS[s.generate]()
                print(f"  {C.G}generated{C.X} ({len(v)} chars)")
                return v, True
            return ("", False) if s.optional else ("", True)
        if raw.lower() == "skip" and s.optional:
            return "", False
        return raw, True

    def _prompt_text(self, s, provided):
        dflt = provided if provided is not None else s.default
        suffix = f" {C.DIM}[{dflt}]{C.X}" if dflt not in (None, "") else (
            f" {C.DIM}[blank to skip]{C.X}" if s.optional else "")
        raw = input(f"  value{suffix}: ").strip()
        if raw == "":
            if dflt not in (None, ""):
                return dflt, True
            return "", (not s.optional)
        return raw, True

    def _prompt_bool(self, s, provided):
        dflt = provided if provided is not None else (s.default if s.default is not None else False)
        dflt = self._coerce(Setting("", "", [], kind="bool"), dflt)
        raw = input(f"  [y/n] {C.DIM}[{'y' if dflt else 'n'}]{C.X}: ").strip().lower()
        if raw == "":
            return dflt
        return raw in ("y", "yes", "1", "true")

    def _prompt_int(self, s, provided):
        dflt = provided if provided is not None else s.default
        while True:
            raw = input(f"  number {C.DIM}[{dflt}]{C.X}: ").strip()
            if raw == "":
                return int(dflt)
            try:
                return int(raw)
            except ValueError:
                print(f"  {C.R}not a number{C.X}")

    def _prompt_choice(self, s, provided):
        dflt = provided if provided is not None else s.default
        print(f"  options: {', '.join(s.choices)}")
        raw = input(f"  choice {C.DIM}[{dflt}]{C.X}: ").strip()
        if raw == "":
            return dflt
        if raw not in s.choices:
            print(f"  {C.Y}'{raw}' not in options — using {dflt}{C.X}")
            return dflt
        return raw


# ── file writers ─────────────────────────────────────────────────────────────

def backup(path: Path):
    if path.exists():
        b = path.with_suffix(path.suffix + f".bak.{int(time.time())}")
        shutil.copy2(path, b)
        print(f"  {C.DIM}backed up {path.name} -> {b.name}{C.X}")


def chmod600(path: Path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def env_apply(env_path: Path, updates: dict):
    """Update/append KEY=value in .env, preserving comments + order."""
    lines = env_path.read_text().splitlines() if env_path.exists() else []
    seen = set()
    for i, ln in enumerate(lines):
        m = re.match(r'^\s*([A-Z0-9_]+)\s*=', ln)
        if m and m.group(1) in updates:
            k = m.group(1)
            lines[i] = f"{k}={updates[k]}"
            seen.add(k)
    new = [k for k in updates if k not in seen]
    if new:
        lines.append("")
        lines.append(f"# ── set by genesis.py {time.strftime('%Y-%m-%d')} ──")
        for k in new:
            lines.append(f"{k}={updates[k]}")
    env_path.write_text("\n".join(lines) + "\n")
    chmod600(env_path)


def secret_file_apply(name: str, value: str):
    d = ROOT / "secrets"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_text(value + "\n")
    chmod600(p)


def _yaml_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if s == "" or re.search(r'[:#{}\[\],&*!|>%@`"\']', s) or s != s.strip():
        return '"' + s.replace('"', '\\"') + '"'
    return s


def set_yaml_value(path: Path, dotted: str, value) -> bool:
    """Set a dotted-path scalar in a YAML file IN PLACE (comments preserved).
    Walks the path by indent; replaces only the leaf line. Returns False if the
    path isn't present (caller warns + leaves the file untouched)."""
    keys = dotted.split(".")
    lines = path.read_text().splitlines()
    start, end, parent_indent = 0, len(lines), -1
    for depth, key in enumerate(keys):
        krx = re.compile(r'^(\s*)' + re.escape(key) + r'\s*:(.*)$')
        found = None
        for i in range(start, end):
            m = krx.match(lines[i])
            if m and len(m.group(1)) > parent_indent:
                found = (i, len(m.group(1)), m.group(2))
                break
        if not found:
            return False
        idx, indent, rest = found
        if depth == len(keys) - 1:
            cm = re.search(r'(\s+#.*)$', rest)
            comment = cm.group(1) if cm else ""
            lines[idx] = " " * indent + key + ": " + _yaml_scalar(value) + comment
            path.write_text("\n".join(lines) + "\n")
            return True
        parent_indent, start, end = indent, idx + 1, len(lines)
        for j in range(idx + 1, len(lines)):
            ln = lines[j]
            if ln.strip() and not ln.lstrip().startswith("#") and \
                    (len(ln) - len(ln.lstrip())) <= indent:
                end = j
                break
    return False


def security_yml_apply(updates: dict, users: Optional[list]):
    """Update config/security.yml: keep jwt_secret as the ${JWT_SECRET} placeholder
    (real value lives in .env/secrets), set auth + rate-limit scalars + users."""
    p = ROOT / "config" / "security.yml"
    data = yaml.safe_load(p.read_text()) if p.exists() else {}
    data = data or {}
    data.setdefault("authentication", {})
    data["authentication"]["jwt_secret"] = "${JWT_SECRET}"
    auth_map = {"authentication.token_expiry_hours": ("authentication", "token_expiry_hours")}
    rate_map = {
        "rate_limiting.enabled": ("rate_limiting", "enabled"),
        "rate_limiting.requests_per_minute": ("rate_limiting", "requests_per_minute"),
        "rate_limiting.burst": ("rate_limiting", "burst"),
    }
    for dotted, val in updates.items():
        for mapping in (auth_map, rate_map):
            if dotted in mapping:
                sec, key = mapping[dotted]
                data.setdefault(sec, {})[key] = val
    if users is not None:
        data["users"] = users
    backup(p)
    p.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
    chmod600(p)


# ── users flow ───────────────────────────────────────────────────────────────

def build_users(answers: dict, interactive: bool) -> tuple[list, list]:
    """Returns (security_users, plaintext_creds). plaintext_creds is shown once."""
    users, creds = [], []

    # Non-interactive: take from answers (each: username, role, api_key? )
    if not interactive:
        for u in answers.get("users", []):
            key = u.get("api_key") or gen_urlsafe(32)
            users.append({"username": u["username"], "role": u["role"],
                          "api_key_hash": sha256(key)})
            if not u.get("api_key"):
                creds.append((u["username"], u["role"], key))
        if not any(u["role"] == "admin" for u in users):
            print(f"{C.Y}⚠ no admin user provided — add one to the answers file{C.X}")
        return users, creds

    hr("Operator users")
    print("Add the people/automation that will use the platform. Each gets an API key\n"
          "(their 'password'). Roles: " + ", ".join(VALID_ROLES) + ".")
    caveat("API keys are hashed with plain SHA-256 (no bcrypt). Prefer GENERATED keys; a "
           "weak typed passphrase is brute-forceable offline if security.yml leaks.")
    while True:
        username = input(f"\n  {C.B}username{C.X} (blank to finish): ").strip()
        if not username:
            break
        role = ""
        while role not in VALID_ROLES:
            role = (input(f"  role {C.DIM}{'/'.join(VALID_ROLES)} [viewer]{C.X}: ").strip()
                    or "viewer").lower()
            if role not in VALID_ROLES:
                print(f"  {C.R}invalid role{C.X}")
        mode = input(f"  API key: [Enter]=generate, or type a custom key: ").strip()
        if mode == "":
            key = gen_urlsafe(32)
            print(f"  {C.G}generated key for {username}{C.X}")
        else:
            key = mode
            caveat("custom key stored as SHA-256 — make it long + random.")
        users.append({"username": username, "role": role, "api_key_hash": sha256(key)})
        creds.append((username, role, key))

    if not any(u["role"] == "admin" for u in users):
        print(f"{C.Y}⚠ You created no 'admin' user — nobody can manage the platform. "
              f"Add one before finishing.{C.X}")
    return users, creds


# ── engine ───────────────────────────────────────────────────────────────────

def run_section(name: str, prompter: Prompter, plan: dict):
    if name == "users":
        return  # handled separately
    settings = SECTIONS.get(name, [])
    if not settings:
        return
    hr(SECTION_TITLES.get(name, name))
    for s in settings:
        value, do_write = prompter.value_for(s)
        if not do_write:
            continue
        for t in s.targets:
            if isinstance(t, Env):
                plan["env"][t.name] = _env_str(value)
            elif isinstance(t, SecretFile):
                plan["secret_files"][t.filename] = str(value)
            elif isinstance(t, Yaml):
                plan["yaml"].setdefault(t.file, []).append((t.path, value))


def _env_str(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def apply_plan(plan: dict, users: Optional[list]):
    hr("Writing configuration")
    # .env
    if plan["env"]:
        env_p = ROOT / ".env"
        backup(env_p)
        env_apply(env_p, plan["env"])
        print(f"  {C.G}.env{C.X} ← {', '.join(sorted(plan['env']))}")
    # secret files
    for fn, val in plan["secret_files"].items():
        secret_file_apply(fn, val)
        print(f"  {C.G}secrets/{fn}{C.X} (0600)")
    # security.yml (auth + rate-limit + users) — handled together
    sec_updates = {}
    for file, items in plan["yaml"].items():
        if file == "security.yml":
            for path, val in items:
                sec_updates[path] = val
    if sec_updates or users is not None:
        security_yml_apply(sec_updates, users)
        print(f"  {C.G}config/security.yml{C.X} (0600)"
              + (f" — {len(users)} users" if users is not None else ""))
    # other yaml files (in-place, comment-preserving)
    for file, items in plan["yaml"].items():
        if file == "security.yml":
            continue
        p = ROOT / "config" / file
        if not p.exists():
            print(f"  {C.Y}config/{file} not found — skipped{C.X}")
            continue
        backup(p)
        for path, val in items:
            ok = set_yaml_value(p, path, val)
            tag = C.G + "ok" + C.X if ok else C.Y + "path not found (edit manually)" + C.X
            print(f"  config/{file}:{path} ← {tag}")


# ── idempotency ──────────────────────────────────────────────────────────────

def already_configured() -> bool:
    """Heuristic: JWT secret is no longer the placeholder/default."""
    env = ROOT / ".env"
    if env.exists():
        m = re.search(r'^JWT_SECRET=(.*)$', env.read_text(), re.M)
        if m and m.group(1).strip() and "change-this" not in m.group(1) \
                and m.group(1).strip() != "${JWT_SECRET}":
            return True
    return False


# ── main ─────────────────────────────────────────────────────────────────────

def cmd_list():
    print(f"{C.B}Configurable settings (genesis sections){C.X}")
    for name in SECTION_ORDER:
        print(f"\n{C.CY}[{name}]{C.X} {SECTION_TITLES.get(name, '')}")
        if name == "users":
            print("  users[] — username, role (viewer/analyst/operator/admin), api_key (generated or typed)")
            continue
        for s in SECTIONS.get(name, []):
            tgt = ", ".join(
                (f"env:{t.name}" if isinstance(t, Env)
                 else f"secret:{t.filename}" if isinstance(t, SecretFile)
                 else f"{t.file}:{t.path}") for t in s.targets)
            opt = " (optional)" if s.optional else ""
            print(f"  • {C.B}{s.name}{C.X}{opt} — {s.label}  {C.DIM}[{tgt}]{C.X}")
            caveat(s.caveat)


def main():
    ap = argparse.ArgumentParser(description="Genesis configuration for the APT THP.")
    ap.add_argument("--answers", help="YAML answers file (keys = setting names, plus users:[])")
    ap.add_argument("--write-answers", metavar="FILE",
                    help="Save the chosen values to FILE for repeatable installs (0600).")
    ap.add_argument("--non-interactive", action="store_true",
                    help="Never prompt; use --answers + defaults + auto-generated secrets.")
    ap.add_argument("--section", action="append", choices=SECTION_ORDER,
                    help="Only (re)configure these section(s). Repeatable.")
    ap.add_argument("--list", action="store_true", help="List every configurable setting + caveat, then exit.")
    ap.add_argument("--force", action="store_true", help="Proceed even if the install looks already configured.")
    args = ap.parse_args()

    if args.list:
        cmd_list()
        return 0

    answers = {}
    if args.answers:
        answers = yaml.safe_load(Path(args.answers).read_text()) or {}

    interactive = not args.non_interactive
    sections = args.section or SECTION_ORDER

    print(f"{C.B}{C.CY}APT Threat Hunting Platform — genesis configuration{C.X}")
    print(f"{C.DIM}root: {ROOT}{C.X}")
    if already_configured() and not args.force and interactive and not args.section:
        print(f"\n{C.Y}This install already looks configured (JWT_SECRET set).{C.X}")
        if input("Reconfigure anyway? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("Aborted. Use --section <name> to change one thing, or --force.")
            return 1

    prompter = Prompter(answers, interactive)
    plan = {"env": {}, "secret_files": {}, "yaml": {}}
    users = None
    creds = []

    for name in SECTION_ORDER:
        if name not in sections:
            continue
        if name == "users":
            users, creds = build_users(answers, interactive)
        else:
            run_section(name, prompter, plan)

    # Apply
    apply_plan(plan, users)

    # Optionally save answers (NON-secret settings + user list w/o keys)
    if args.write_answers:
        out = {k: v for k, v in answers.items()}
        for name in sections:
            for s in SECTIONS.get(name, []):
                if s.kind != "secret" and s.name in plan["env"]:
                    out[s.name] = plan["env"][s.name]
        ap_p = Path(args.write_answers)
        ap_p.write_text(yaml.safe_dump(out, sort_keys=False))
        chmod600(ap_p)
        print(f"\n{C.G}answers template saved -> {ap_p}{C.X} {C.DIM}(secrets excluded){C.X}")

    # Credentials summary (shown once)
    if creds:
        hr("USER CREDENTIALS — shown once, store them now")
        for u, role, key in creds:
            print(f"  {C.B}{u}{C.X} ({role})  api_key: {C.G}{key}{C.X}")
        if interactive and input("\nWrite these to secrets/genesis_credentials.txt (0600)? [y/N]: ")\
                .strip().lower() in ("y", "yes"):
            cp = ROOT / "secrets" / "genesis_credentials.txt"
            (ROOT / "secrets").mkdir(exist_ok=True)
            cp.write_text("username,role,api_key\n" +
                          "".join(f"{u},{r},{k}\n" for u, r, k in creds))
            chmod600(cp)
            print(f"  {C.G}{cp}{C.X} — DELETE after distributing the keys.")

    hr("Done")
    print("Next: review .env / config/security.yml, set the SAME Wazuh passwords in your\n"
          "Wazuh stack, then start the platform. JWT_SECRET is read from .env via the\n"
          "${JWT_SECRET} placeholder in security.yml.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
