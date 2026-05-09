# features/dns_features.py
"""
DNS exfiltration feature extractor.

Produces features across six categories that capture the known signatures
of DNS tunneling (iodine, dnscat2), DNS C2 beaconing (Cobalt Strike),
and slow-drip DNS exfiltration.

Feature categories:
  1. Volume           — query rate, total count
  2. Query encoding   — entropy, length, base64/hex/numeric patterns, label analysis
  3. Domain targeting — concentration on a single domain vs. spreading
  4. Record type      — TXT/NULL/MX/ANY usage signals tunneling protocol
  5. Response         — NXDOMAIN ratio, response sizes, TTL (fast-flux C2)
  6. Temporal         — inter-query intervals (beaconing has low coefficient of variation)
  7. Process context  — non-browser processes making DNS queries
  8. Network context  — DNS to non-standard ports

Input: list[NormalizedEvent] where event_type == "dns_query"
Output: dict[str, float]  (all values are floats for XGBoost DMatrix)
"""

import math
import re
import statistics
from collections import Counter, defaultdict
from typing import Optional

from shared.interfaces import BaseFeatureExtractor
from shared.schemas import NormalizedEvent

# Browser and OS processes that legitimately generate high DNS volume.
# Non-browser, non-system processes making many DNS queries is suspicious.
_BENIGN_DNS_PROCESSES = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "iexplore.exe", "svchost.exe", "backgroundtaskhost.exe",
    "searchindexer.exe", "onedrive.exe", "teams.exe", "slack.exe",
    "outlook.exe", "msiexec.exe", "wuauclt.exe", "windowsupdate.exe",
    "runtimebroker.exe",
})

# Record types associated with DNS tunneling protocols
_TUNNELING_RECORD_TYPES = frozenset({"TXT", "NULL", "MX", "CNAME", "ANY"})


class DnsFeatureExtractor(BaseFeatureExtractor):

    def name(self) -> str:
        return "dns"

    def required_event_types(self) -> list[str]:
        return ["dns_query"]

    def extract(self, events: list[NormalizedEvent]) -> dict[str, float]:
        queries = [e.dns_query for e in events if e.dns_query]
        if not queries:
            return self._empty_features()

        return {
            **self._volume_features(events, queries),
            **self._encoding_features(events, queries),
            **self._domain_features(queries),
            **self._record_type_features(events),
            **self._response_features(events),
            **self._temporal_features(events, queries),
            **self._process_features(events),
            **self._network_features(events),
        }

    # ── 1. Volume ─────────────────────────────────────────────────────────────

    def _volume_features(self, events: list[NormalizedEvent], queries: list[str]) -> dict:
        n = len(queries)
        # Queries per minute over the event window
        if len(events) >= 2:
            ts_sorted = sorted(e.timestamp for e in events)
            window_seconds = max(
                (ts_sorted[-1] - ts_sorted[0]).total_seconds(), 1.0
            )
            rate = (n / window_seconds) * 60.0
        else:
            rate = 0.0

        return {
            "query_count":          float(n),
            "query_rate_per_minute": rate,
        }

    # ── 2. Query encoding ─────────────────────────────────────────────────────

    def _encoding_features(self, events: list[NormalizedEvent], queries: list[str]) -> dict:
        n = len(queries)

        # Subdomain portion = everything to the left of the last two labels
        subdomains = [self._subdomain(q) for q in queries]

        # Per-query entropy
        entropies = [self._entropy(q) for q in queries]

        # Label-level analysis (DNS labels are dot-separated parts)
        all_labels   = [lbl for q in queries for lbl in q.rstrip(".").split(".")]
        label_lengths = [len(l) for l in all_labels] if all_labels else [0]
        label_entropies = [self._entropy(l) for l in all_labels if len(l) > 3]

        return {
            # Whole-query length
            "avg_query_length":         sum(len(q) for q in queries) / n,
            "max_query_length":         float(max(len(q) for q in queries)),

            # Shannon entropy on full query string
            "avg_entropy":              sum(entropies) / n,
            "max_entropy":              max(entropies),

            # Subdomain depth (dot count) — tunneling uses deeply nested labels
            "avg_subdomain_depth":      sum(q.count(".") for q in queries) / n,

            # Individual label analysis
            # Tunneling tools fill labels to the 63-char maximum
            "max_label_length":         float(max(label_lengths)),
            "avg_label_length":         sum(label_lengths) / max(len(label_lengths), 1),
            # Per-label entropy (encoded labels have near-uniform char distribution)
            "label_entropy_max":        max(label_entropies) if label_entropies else 0.0,

            # Uniqueness — tunneling generates a new encoded subdomain per chunk
            "unique_subdomain_ratio":   len(set(queries)) / n,

            # Encoding pattern detection in the subdomain portion
            "base64_pattern_count":     float(sum(1 for s in subdomains if self._has_base64(s))),
            "hex_pattern_count":        float(sum(1 for s in subdomains if self._has_hex(s))),
            "numeric_ratio":            sum(self._numeric_ratio(s) for s in subdomains) / n,
            # Fraction of subdomains that contain digits — base64 and hex both have digits
            "subdomain_has_numbers_ratio": sum(
                1 for s in subdomains if any(c.isdigit() for c in s)
            ) / n,
        }

    # ── 3. Domain targeting ───────────────────────────────────────────────────

    def _domain_features(self, queries: list[str]) -> dict:
        n = len(queries)

        # Group queries by base domain (last two labels, e.g., "attacker.com")
        domain_counts: Counter = Counter(self._base_domain(q) for q in queries)
        unique_base   = len(domain_counts)
        top_count     = domain_counts.most_common(1)[0][1]

        # For the most-targeted domain, count unique subdomain prefixes
        top_domain = domain_counts.most_common(1)[0][0]
        subdomains_for_top = [
            self._subdomain(q) for q in queries if self._base_domain(q) == top_domain
        ]
        unique_subs_for_top = len(set(subdomains_for_top))

        return {
            # How many distinct base domains are queried?
            # Tunneling concentrates on ONE domain; normal traffic spreads across many.
            "unique_base_domains":              float(unique_base),
            # Fraction of all queries going to the single most-targeted domain.
            # Tunneling: close to 1.0.  Normal browsing: close to 0.
            "top_domain_query_ratio":           top_count / n,
            # Unique subdomain prefixes for the top domain — high = data chunked into labels.
            "max_unique_subdomains_per_domain": float(unique_subs_for_top),
        }

    # ── 4. Record type ────────────────────────────────────────────────────────

    def _record_type_features(self, events: list[NormalizedEvent]) -> dict:
        n_total = len(events)
        types   = [e.dns_query_type or "" for e in events]

        def _ratio(t: str) -> float:
            return sum(1 for x in types if x.upper() == t) / n_total

        # Count of distinct record types used — tunneling typically uses unusual types
        distinct_types = len({t for t in types if t})

        return {
            "txt_record_ratio":    _ratio("TXT"),
            "null_record_ratio":   _ratio("NULL"),
            "mx_record_ratio":     _ratio("MX"),
            "cname_record_ratio":  _ratio("CNAME"),
            "any_record_ratio":    _ratio("ANY"),
            # Tunneling record types (TXT + NULL + MX + CNAME + ANY) combined
            "tunneling_type_ratio": sum(
                1 for t in types if t.upper() in _TUNNELING_RECORD_TYPES
            ) / n_total,
            "record_type_count":   float(distinct_types),
        }

    # ── 5. Response analysis ──────────────────────────────────────────────────

    def _response_features(self, events: list[NormalizedEvent]) -> dict:
        n = len(events)

        # Response sizes
        sizes = [e.bytes_received for e in events]
        nonzero_sizes = [s for s in sizes if s > 0]

        avg_size = sum(sizes) / n
        max_size = float(max(sizes))
        size_var = (
            statistics.variance(sizes) if len(sizes) >= 2 else 0.0
        )

        # NXDOMAIN ratio — probe queries return NXDOMAIN; some tunneling protocols
        # use NXDOMAIN as a signal that the chunk was received by the C2 server
        nxdomain_count = sum(
            1 for e in events if e.dns_response_code == "NXDOMAIN"
        )

        # TTL analysis
        ttls = [e.dns_ttl for e in events if e.dns_ttl is not None]
        # Fast-flux: TTL < 60s means C2 infrastructure rotates IPs rapidly
        fast_flux_count = sum(1 for t in ttls if t < 60)
        min_ttl  = float(min(ttls)) if ttls else -1.0
        ttl_var  = statistics.variance(ttls) if len(ttls) >= 2 else 0.0

        return {
            "avg_response_size":   avg_size,
            "max_response_size":   max_size,
            "response_variance":   float(size_var),
            "nxdomain_ratio":      nxdomain_count / n,
            # Fast-flux ratio: fraction of responses with TTL < 60s
            "fast_flux_ratio":     (fast_flux_count / max(len(ttls), 1)) if ttls else 0.0,
            "min_ttl":             min_ttl,
            "ttl_variance":        float(ttl_var),
        }

    # ── 6. Temporal (beaconing detection) ─────────────────────────────────────

    def _temporal_features(self, events: list[NormalizedEvent], queries: list[str]) -> dict:
        """
        DNS beaconing: a C2 agent queries its server at regular intervals.
        Signature: low inter-query interval variance (coefficient of variation ≈ 0).
        Normal DNS: highly irregular intervals driven by user browsing behaviour.
        """
        if len(events) < 3:
            return {
                "inter_query_interval_mean": 0.0,
                "inter_query_interval_cv":   0.0,
            }

        sorted_ts = sorted(e.timestamp for e in events)
        intervals = [
            (sorted_ts[i + 1] - sorted_ts[i]).total_seconds()
            for i in range(len(sorted_ts) - 1)
        ]
        # Remove zero intervals (simultaneous events / same second)
        intervals = [x for x in intervals if x > 0] or [0.0]

        mean = statistics.mean(intervals)
        cv   = (statistics.stdev(intervals) / mean) if mean > 0 and len(intervals) >= 2 else 0.0

        return {
            # Mean time between queries — beaconing has consistent, short intervals
            "inter_query_interval_mean": mean,
            # Coefficient of variation — beaconing: low CV (regular); browsing: high CV
            "inter_query_interval_cv":   cv,
        }

    # ── 7. Process context ────────────────────────────────────────────────────

    def _process_features(self, events: list[NormalizedEvent]) -> dict:
        n = len(events)
        # Extract lowercase basename from full image path
        proc_names = [
            self._proc_basename(e.process_name)
            for e in events
            if e.process_name
        ]

        if not proc_names:
            return {"unique_process_count": 0.0, "non_browser_dns_ratio": 0.0}

        non_browser = sum(1 for p in proc_names if p not in _BENIGN_DNS_PROCESSES)

        return {
            # 1 non-browser process making all DNS queries = suspicious
            "unique_process_count":   float(len(set(proc_names))),
            # High ratio = custom tool (not a browser/OS) is doing the querying
            "non_browser_dns_ratio":  non_browser / n,
        }

    # ── 8. Network context ────────────────────────────────────────────────────

    def _network_features(self, events: list[NormalizedEvent]) -> dict:
        n = len(events)
        # DNS over ports other than 53: DoT (853), DoH (443), or covert channels
        non_std = sum(
            1 for e in events
            if e.dest_port is not None and e.dest_port != 53
        )
        return {
            "non_standard_dns_ratio": non_std / n,
        }

    # ── Low-level helpers ─────────────────────────────────────────────────────

    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text.lower())
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def _subdomain(self, query: str) -> str:
        """Everything to the left of the base domain (last two labels)."""
        parts = query.rstrip(".").split(".")
        if len(parts) <= 2:
            return ""
        return ".".join(parts[:-2])

    def _base_domain(self, query: str) -> str:
        parts = query.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else query

    def _has_base64(self, text: str) -> bool:
        return bool(re.search(r"[A-Za-z0-9+/]{20,}={0,2}", text))

    def _has_hex(self, text: str) -> bool:
        return bool(re.search(r"[0-9a-f]{16,}", text.lower()))

    def _numeric_ratio(self, text: str) -> float:
        if not text:
            return 0.0
        return sum(1 for c in text if c.isdigit()) / len(text)

    def _proc_basename(self, path: Optional[str]) -> str:
        if not path:
            return ""
        # Handle both Windows backslash and Unix paths
        return path.replace("\\", "/").split("/")[-1].lower()

    # ── Empty feature vector ──────────────────────────────────────────────────

    def _empty_features(self) -> dict[str, float]:
        return {k: 0.0 for k in [
            # Volume
            "query_count", "query_rate_per_minute",
            # Encoding
            "avg_query_length", "max_query_length",
            "avg_entropy", "max_entropy",
            "avg_subdomain_depth",
            "max_label_length", "avg_label_length", "label_entropy_max",
            "unique_subdomain_ratio",
            "base64_pattern_count", "hex_pattern_count",
            "numeric_ratio", "subdomain_has_numbers_ratio",
            # Domain targeting
            "unique_base_domains", "top_domain_query_ratio",
            "max_unique_subdomains_per_domain",
            # Record type
            "txt_record_ratio", "null_record_ratio", "mx_record_ratio",
            "cname_record_ratio", "any_record_ratio",
            "tunneling_type_ratio", "record_type_count",
            # Response
            "avg_response_size", "max_response_size", "response_variance",
            "nxdomain_ratio", "fast_flux_ratio", "min_ttl", "ttl_variance",
            # Temporal
            "inter_query_interval_mean", "inter_query_interval_cv",
            # Process
            "unique_process_count", "non_browser_dns_ratio",
            # Network
            "non_standard_dns_ratio",
        ]}
