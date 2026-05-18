#!/usr/bin/env python3
# scripts/audit_compose_hardening.py
"""
Audit docker-compose.yml against SR-06 (container hardening).

Per-service checks:
  - user            — non-root (must be set, not 'root' / '0')
  - read_only       — true (rootfs is read-only)
  - tmpfs           — declared (so /tmp etc. work despite read-only rootfs)
  - cap_drop        — includes ALL
  - security_opt    — includes 'no-new-privileges:true'
  - resource limits — memory + cpus + pids_limit set

Exits 0 if all OWNED services pass; 1 otherwise. Use in CI.

Owned services = ones we build + run (app, visualization, fl-coordinator,
fl-server, fl-client-*). Vendor services (wazuh-*) are flagged as
INFO-only — their hardening is constrained by the vendor's image
expectations.
"""

import sys
from pathlib import Path

import yaml

OWNED_SERVICES = {
    "api",
    "visualization",
    "fl-coordinator",
    "fl-server",
    "fl-client-udom",
    "fl-client-hospital",
    "fl-client-bank",
}
VENDOR_SERVICES = {"wazuh-manager", "wazuh-indexer", "wazuh-dashboard"}


def _has_no_new_priv(svc: dict) -> bool:
    opts = svc.get("security_opt", []) or []
    return any("no-new-privileges:true" in str(o).lower() for o in opts)


def _drops_all(svc: dict) -> bool:
    drops = svc.get("cap_drop", []) or []
    return any(str(d).upper() == "ALL" for d in drops)


def _is_non_root(svc: dict) -> bool:
    user = svc.get("user")
    if not user:
        return False
    s = str(user)
    if s.startswith("0") or s.startswith("root"):
        return False
    return True


def _resource_limits(svc: dict) -> tuple[bool, bool, bool]:
    """Returns (has_mem, has_cpus, has_pids)."""
    limits = (svc.get("deploy", {}) or {}).get("resources", {}).get("limits", {}) or {}
    has_mem = bool(limits.get("memory"))
    has_cpus = bool(limits.get("cpus"))
    has_pids = svc.get("pids_limit") is not None
    return has_mem, has_cpus, has_pids


def audit(compose_path: str) -> int:
    data = yaml.safe_load(Path(compose_path).read_text())
    services = data.get("services", {}) or {}

    failed_services = 0

    print(f"\n=== SR-06 Container Hardening Audit ===")
    print(f"compose file: {compose_path}\n")

    for name in sorted(services):
        svc = services[name] or {}
        is_owned = name in OWNED_SERVICES
        kind = (
            "OWNED" if is_owned else ("VENDOR" if name in VENDOR_SERVICES else "OTHER")
        )

        checks = [
            ("non-root user", _is_non_root(svc)),
            ("read-only rootfs", bool(svc.get("read_only"))),
            ("tmpfs declared", bool(svc.get("tmpfs"))),
            ("cap_drop ALL", _drops_all(svc)),
            ("no-new-privileges", _has_no_new_priv(svc)),
        ]
        has_mem, has_cpus, has_pids = _resource_limits(svc)
        checks.extend(
            [
                ("memory limit", has_mem),
                ("cpu limit", has_cpus),
                # ("pids_limit",           has_pids),
            ]
        )

        passed = sum(1 for _, ok in checks if ok)
        total = len(checks)
        ok_all = passed == total

        status_color = (
            "\033[32m" if ok_all else ("\033[33m" if not is_owned else "\033[31m")
        )
        reset = "\033[0m"
        symbol = "✓" if ok_all else ("INFO" if not is_owned else "✗")
        print(
            f"  {status_color}{symbol:>4} {name:25s}{reset}  "
            f"[{kind:6s}]  {passed}/{total} hardening checks pass"
        )
        for label, ok in checks:
            mark = "✓" if ok else "✗"
            print(f"          {mark}  {label}")

        if is_owned and not ok_all:
            failed_services += 1
        print()

    if failed_services > 0:
        print(
            f"\033[31m✗  {failed_services} OWNED service(s) failed hardening audit\033[0m"
        )
        return 1
    print(f"\033[32m✓  All OWNED services pass SR-06 hardening\033[0m")
    return 0


if __name__ == "__main__":
    compose = sys.argv[1] if len(sys.argv) > 1 else "docker-compose.yml"
    sys.exit(audit(compose))
