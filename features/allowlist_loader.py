# features/allowlist_loader.py
"""
Stat()-based hot-reload loader for config/allowlists.yml.

Why not yaml-watchdog? Feature extractors call this on every window. A 1-syscall
stat() check + cached parse keeps the hot path ~free while still letting an
operator edit the YAML without a restart. If the file is missing or malformed,
we silently fall back to the built-in defaults — never crash the detector loop
over a bad allowlist edit.
"""

import os
from pathlib import Path
from typing import Optional

import yaml

from shared.logging import get_logger

logger = get_logger("features.allowlist_loader")


_CACHE: dict = {}
_MTIME: float = 0.0
_PATH: Optional[Path] = None


def _resolve_path() -> Path:
    """Honour APT_ALLOWLISTS_PATH for tests, else config/allowlists.yml."""
    override = os.environ.get("APT_ALLOWLISTS_PATH")
    if override:
        return Path(override)
    return Path("config/allowlists.yml")


def _maybe_reload() -> None:
    global _CACHE, _MTIME, _PATH
    if _PATH is None:
        _PATH = _resolve_path()
    try:
        mtime = _PATH.stat().st_mtime
    except FileNotFoundError:
        if _CACHE:
            return
        _CACHE = {}
        return
    if mtime == _MTIME and _CACHE:
        return
    try:
        with _PATH.open("r") as f:
            parsed = yaml.safe_load(f) or {}
        if not isinstance(parsed, dict):
            logger.warning("Allowlist file must be a mapping", path=str(_PATH))
            return
        _CACHE = parsed
        _MTIME = mtime
    except Exception as e:
        logger.warning("Failed to reload allowlist", path=str(_PATH), error=str(e))


def get_list(key: str, default: list) -> list:
    _maybe_reload()
    val = _CACHE.get(key)
    if not isinstance(val, list):
        return default
    return [str(v).lower() for v in val]
