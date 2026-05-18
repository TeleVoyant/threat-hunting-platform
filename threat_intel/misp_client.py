# threat_intel/misp_client.py
"""
MISP IoC correlation client.

Two operating modes (FR-06):

  1. LIVE: fetches IoCs from a MISP server's REST API, caches them in
     memory with TTL, queries on each detection.
  2. FILE: loads IoCs from a local JSON file (./threat_intel/iocs.json
     by default). Useful for FYP demos without a running MISP instance,
     or for orgs that maintain their own static IoC list.

Both modes expose the same `match()` interface:

    matches = client.match(
        ips=["10.0.0.5"],
        domains=["evil.attacker.com"],
        hashes=["sha256:abc..."],
    )
    # → list[dict]: each match is {indicator, type, threat_type, source}

The Enricher calls match() during alert enrichment; matches go into
`EnrichedAlert.ioc_matches`.

Configuration (config/platform.yml):

    threat_intel:
      misp:
        enabled: true
        mode: file               # 'live' or 'file'
        cache_ttl_seconds: 3600  # how long to keep MISP IoCs in memory
        # mode=live:
        url: https://misp.example.com
        api_key: ${MISP_API_KEY}
        verify_ssl: true
        # mode=file:
        path: threat_intel/iocs.json
"""

import json
import os
import time
from pathlib import Path
from threading import Lock
from typing import Optional

from shared.logging import get_logger

logger = get_logger("threat_intel.misp_client")


# IoC type buckets we support
_IOC_TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256"}


class MispClient:
    """
    In-memory IoC index. Refreshed on TTL expiry from configured source.

    Thread-safe: index lookups + refreshes are guarded by a lock.
    """

    def __init__(
        self,
        mode: str = "file",
        *,
        path: Optional[str] = None,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
        cache_ttl_seconds: int = 3600,
    ):
        if mode not in {"file", "live"}:
            raise ValueError(f"mode must be 'file' or 'live', got {mode!r}")
        self.mode = mode
        self.path = path or "threat_intel/iocs.json"
        self.url = (url or "").rstrip("/")
        self.api_key = api_key or ""
        self.verify_ssl = verify_ssl
        self.ttl = cache_ttl_seconds

        self._lock = Lock()
        self._loaded_at: float = 0.0
        # The index is {type: {indicator: {threat_type, source, ...}}}
        self._index: dict[str, dict[str, dict]] = {t: {} for t in _IOC_TYPES}

    # ── Public API ─────────────────────────────────────────────────────────

    def match(
        self,
        *,
        ips:     Optional[list[str]] = None,
        domains: Optional[list[str]] = None,
        urls:    Optional[list[str]] = None,
        hashes:  Optional[list[str]] = None,
    ) -> list[dict]:
        """
        Look up the supplied indicators against the loaded IoC set.
        Returns a list of match records (one per indicator that hit).

        Args:
            ips:     plain IP strings (v4 or v6 — we don't try to normalise)
            domains: lowercased base domains
            hashes:  string of form 'md5:<hex>', 'sha1:<hex>', 'sha256:<hex>'
        """
        self._refresh_if_stale()
        out: list[dict] = []

        with self._lock:
            for ip in ips or []:
                hit = self._index["ip"].get(ip)
                if hit:
                    out.append({"indicator": ip, "type": "ip", **hit})

            for d in domains or []:
                d_low = d.lower()
                hit = self._index["domain"].get(d_low)
                if hit:
                    out.append({"indicator": d_low, "type": "domain", **hit})

            for u in urls or []:
                hit = self._index["url"].get(u)
                if hit:
                    out.append({"indicator": u, "type": "url", **hit})

            for h in hashes or []:
                if ":" in h:
                    htype, val = h.split(":", 1)
                    htype = htype.lower()
                    if htype in {"md5", "sha1", "sha256"}:
                        hit = self._index[htype].get(val.lower())
                        if hit:
                            out.append({"indicator": val.lower(),
                                        "type": htype, **hit})

        return out

    def stats(self) -> dict:
        """For dashboard / health endpoints."""
        with self._lock:
            return {
                "mode":           self.mode,
                "loaded_at":      self._loaded_at,
                "ioc_counts":     {t: len(self._index[t]) for t in _IOC_TYPES},
                "total_iocs":     sum(len(v) for v in self._index.values()),
                "cache_age_secs": (time.time() - self._loaded_at) if self._loaded_at else None,
            }

    # ── Loaders ────────────────────────────────────────────────────────────

    def _refresh_if_stale(self) -> None:
        with self._lock:
            if time.time() - self._loaded_at < self.ttl:
                return
        # Loading happens outside the lock so other reads aren't blocked
        try:
            if self.mode == "file":
                index = self._load_from_file()
            else:
                index = self._load_from_misp_api()
        except Exception as e:
            logger.warning("IoC refresh failed — keeping stale index",
                            mode=self.mode, error=str(e))
            return

        with self._lock:
            self._index = index
            self._loaded_at = time.time()
        counts = {t: len(index[t]) for t in _IOC_TYPES if index[t]}
        logger.info("IoC index refreshed", mode=self.mode, counts=counts)

    def _load_from_file(self) -> dict[str, dict[str, dict]]:
        """
        Local JSON format:
            [
              {"type": "ip", "indicator": "10.0.0.5",
               "threat_type": "C2", "source": "internal-ti"},
              {"type": "domain", "indicator": "attacker.com",
               "threat_type": "phishing", "source": "internal-ti"},
              {"type": "sha256", "indicator": "abc123...",
               "threat_type": "ransomware", "source": "internal-ti"}
            ]
        """
        p = Path(self.path)
        if not p.exists():
            logger.warning("MISP IoC file not found — empty index", path=self.path)
            return {t: {} for t in _IOC_TYPES}
        items = json.loads(p.read_text())
        return self._build_index(items)

    def _load_from_misp_api(self) -> dict[str, dict[str, dict]]:
        """
        Fetch from MISP /attributes/restSearch endpoint.

        Pulls last 30 days of network indicators by default. Real
        production deployments would tune `last`, `tags`, `event_id`, etc.
        """
        if not self.url:
            raise RuntimeError("MISP url not configured")
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx not installed — cannot fetch from MISP")

        endpoint = f"{self.url}/attributes/restSearch"
        body = {
            "returnFormat":   "json",
            "type":           ["ip-src", "ip-dst", "domain", "hostname",
                                "url", "md5", "sha1", "sha256"],
            "last":           "30d",
            "to_ids":         True,
            "enforceWarninglist": True,
        }
        headers = {
            "Authorization": self.api_key,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }
        with httpx.Client(timeout=30.0, verify=self.verify_ssl) as c:
            r = c.post(endpoint, headers=headers, json=body)
            r.raise_for_status()
            data = r.json()

        # MISP response: {"response": {"Attribute": [{...}, ...]}}
        attributes = (data.get("response", {}) or {}).get("Attribute", []) or []
        items = []
        for a in attributes:
            misp_type = a.get("type", "").lower()
            our_type = _MISP_TYPE_MAP.get(misp_type)
            if not our_type:
                continue
            items.append({
                "type":        our_type,
                "indicator":   a.get("value", ""),
                "threat_type": a.get("category", ""),
                "source":      f"misp:event_{a.get('event_id', '?')}",
                "first_seen":  a.get("first_seen"),
                "last_seen":   a.get("last_seen"),
            })
        return self._build_index(items)

    @staticmethod
    def _build_index(items: list[dict]) -> dict[str, dict[str, dict]]:
        idx: dict[str, dict[str, dict]] = {t: {} for t in _IOC_TYPES}
        for it in items:
            t   = (it.get("type") or "").lower()
            ind = (it.get("indicator") or "").strip()
            if t not in _IOC_TYPES or not ind:
                continue
            normalised = ind.lower() if t in {"domain", "url", "md5", "sha1", "sha256"} else ind
            idx[t][normalised] = {
                "threat_type": it.get("threat_type"),
                "source":      it.get("source", "unknown"),
                "first_seen":  it.get("first_seen"),
                "last_seen":   it.get("last_seen"),
            }
        return idx


# MISP attribute type → our 6-bucket type
_MISP_TYPE_MAP = {
    "ip-src":    "ip",
    "ip-dst":    "ip",
    "ip":        "ip",
    "domain":    "domain",
    "hostname":  "domain",
    "url":       "url",
    "md5":       "md5",
    "sha1":      "sha1",
    "sha256":    "sha256",
}
