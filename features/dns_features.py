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

from features.allowlist_loader import get_list
from shared.interfaces import BaseFeatureExtractor
from shared.schemas import NormalizedEvent

# Default browser/OS processes that legitimately generate high DNS volume.
# Real list is loaded from config/allowlists.yml on each window (q) — this
# constant is the fall-back when the file is missing or malformed.
_DEFAULT_BENIGN_DNS_PROCESSES = (
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "iexplore.exe", "svchost.exe", "backgroundtaskhost.exe",
    "searchindexer.exe", "onedrive.exe", "teams.exe", "slack.exe",
    "outlook.exe", "msiexec.exe", "wuauclt.exe", "windowsupdate.exe",
    "runtimebroker.exe",
)

# Public DoH / DoT resolvers that legitimately accept queries on non-port-53.
# Excluded from `non_standard_dns_ratio` (p).
_DEFAULT_PUBLIC_RESOLVERS = (
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
)

# Record types associated with DNS tunneling protocols
_TUNNELING_RECORD_TYPES = frozenset({"TXT", "NULL", "MX", "CNAME", "ANY"})


def _is_consonant(c: str) -> bool:
    return c.isalpha() and c.lower() not in "aeiouy"


def _max_run(text: str, predicate) -> int:
    """Longest contiguous run in `text` where `predicate(char)` is true."""
    best = cur = 0
    for c in text:
        if predicate(c):
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


class DnsFeatureExtractor(BaseFeatureExtractor):

    # Same fixed-window principle as AuthFeatureExtractor: rate denominator
    # is the configured analytic window, not the event span (d).
    WINDOW_SECONDS = 5 * 60

    def name(self) -> str:
        return "dns"

    def required_event_types(self) -> list[str]:
        return ["dns_query"]

    def extract(self, events: list[NormalizedEvent]) -> dict[str, float]:
        # Always start from the canonical empty schema and overlay computed
        # values. This guarantees a single key order across every code path
        # — without it, the empty-fallback path and the full-extract path
        # can produce dicts with the same keys in different order, which
        # makes the trainer's strict `list(keys) != feature_names` check
        # explode mid-run.
        result = self._empty_features()

        queries = [e.dns_query for e in events if e.dns_query]
        if not queries:
            # No queryName at all (DNS replies, Sysmon EID 22 with empty
            # queryName). We can still compute the event-level features (g).
            if events:
                result.update(self._response_features(events))
                result.update(self._process_features(events))
                result.update(self._network_features(events))
            return result

        result.update(self._volume_features(events, queries))
        result.update(self._encoding_features(events, queries))
        result.update(self._domain_features(queries))
        result.update(self._record_type_features(events))
        result.update(self._response_features(events))
        result.update(self._temporal_features(events, queries))
        result.update(self._process_features(events))
        result.update(self._network_features(events))
        result.update(self._dga_features(queries))
        result.update(self._nx_funnel_features(events))
        return result

    # ── 1. Volume ─────────────────────────────────────────────────────────────

    def _volume_features(self, events: list[NormalizedEvent], queries: list[str]) -> dict:
        n = len(queries)
        # Queries per minute, computed against the fixed analytic window
        # (not the empirical event span which gave 180/min for 3 events in 1s).
        rate = (n / self.WINDOW_SECONDS) * 60.0
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

    # ── DGA / encoding likelihood (n) ─────────────────────────────────────────

    def _dga_features(self, queries: list[str]) -> dict:
        """
        Cheap DGA proxies without shipping a 4-gram English corpus:
          * consonant_run_max  — random-looking labels have long consonant
            sprints (DGA "kx7d9zlmwp"); English words rarely exceed 4.
          * vowel_ratio_min    — DGA / hex-encoded labels skew low on vowels;
            English averages ~0.38.
          * digit_letter_run   — alternating digit/letter runs (base32-ish
            encoding) are common in tunneling protocols.
        """
        if not queries:
            return {
                "consonant_run_max": 0.0,
                "vowel_ratio_min":   1.0,
                "digit_letter_run_max": 0.0,
            }
        consonant_runs = []
        vowel_ratios = []
        dl_runs = []
        for q in queries:
            sub = self._subdomain(q) or q.split(".")[0]
            # Per-label, not per-query, so leetspeak doesn't get drowned out
            for label in sub.split(".") if sub else [q.split(".")[0]]:
                low = label.lower()
                if not low:
                    continue
                consonant_runs.append(_max_run(low, _is_consonant))
                vowels = sum(1 for c in low if c in "aeiouy")
                letters = sum(1 for c in low if c.isalpha())
                vowel_ratios.append(vowels / letters if letters else 1.0)
                dl_runs.append(_max_run(low, lambda c: c.isalnum()))
        return {
            "consonant_run_max":     float(max(consonant_runs) if consonant_runs else 0),
            "vowel_ratio_min":       float(min(vowel_ratios) if vowel_ratios else 1.0),
            "digit_letter_run_max":  float(max(dl_runs) if dl_runs else 0),
        }

    # ── NXDOMAIN-subdomain funnel (m) ─────────────────────────────────────────

    def _nx_funnel_features(self, events: list[NormalizedEvent]) -> dict:
        """
        Iodine / dnscat2 generate bursts of NXDOMAINs across distinct
        subdomains of one base — the single highest-signal tunneling feature.
        We compute it for the most-targeted base domain in the window.
        """
        coded = [e for e in events if e.dns_query and e.dns_response_code]
        if not coded:
            return {"nx_subdomains_per_top_domain": 0.0,
                    "nx_top_domain_query_ratio":    0.0}
        by_base: dict[str, list] = {}
        for e in coded:
            by_base.setdefault(self._base_domain(e.dns_query), []).append(e)
        top_base = max(by_base, key=lambda d: len(by_base[d]))
        top_events = by_base[top_base]
        nx_subs = {
            self._subdomain(e.dns_query)
            for e in top_events
            if e.dns_response_code == "NXDOMAIN"
        }
        nx_subs.discard("")
        return {
            "nx_subdomains_per_top_domain": float(len(nx_subs)),
            "nx_top_domain_query_ratio":    len(top_events) / len(coded),
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
        avg_size = sum(sizes) / n if n else 0.0
        max_size = float(max(sizes)) if sizes else 0.0
        size_var = statistics.variance(sizes) if len(sizes) >= 2 else 0.0

        # NXDOMAIN ratio — only count over events that *have* a response code
        # (e). Sysmon-only telemetry mixed with DNS-Client telemetry would
        # otherwise dilute the ratio because Sysmon EID 22 often arrives with
        # response_code defaulted to NOERROR.
        coded = [e for e in events if e.dns_response_code]
        if coded:
            nxdomain_count = sum(1 for e in coded if e.dns_response_code == "NXDOMAIN")
            nx_ratio = nxdomain_count / len(coded)
        else:
            nx_ratio = 0.0

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
            "nxdomain_ratio":      nx_ratio,
            "fast_flux_ratio":     (fast_flux_count / len(ttls)) if ttls else 0.0,
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

        benign = frozenset(
            get_list("dns_benign_processes", list(_DEFAULT_BENIGN_DNS_PROCESSES))
        )
        non_browser = sum(1 for p in proc_names if p not in benign)

        return {
            # 1 non-browser process making all DNS queries = suspicious
            "unique_process_count":   float(len(set(proc_names))),
            # High ratio = custom tool (not a browser/OS) is doing the querying
            "non_browser_dns_ratio":  non_browser / n,
        }

    # ── 8. Network context ────────────────────────────────────────────────────

    def _network_features(self, events: list[NormalizedEvent]) -> dict:
        n = len(events)
        # DNS over ports other than 53: DoT (853), DoH (443), or covert
        # channels. Exclude public DoH/DoT resolvers (p) so Firefox-DoH and
        # Cloudflare 1.1.1.1/853 don't count as "covert".
        resolvers = frozenset(
            get_list("public_resolvers", list(_DEFAULT_PUBLIC_RESOLVERS))
        )
        non_std = sum(
            1 for e in events
            if e.dest_port is not None and e.dest_port != 53
            and (e.dest_ip or "") not in resolvers
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
        # Old regex matched any alphanumeric run ≥20 chars — flagged S3 keys,
        # CDN hashes, googleapis shards. Require a high-entropy span AND
        # either real padding or +/ chars (which legitimate alphanumeric
        # subdomains will not contain) (f).
        m = re.search(r"[A-Za-z0-9+/]{20,}={0,2}", text)
        if not m:
            return False
        span = m.group(0)
        if "+" in span or "/" in span or span.endswith("=") or span.endswith("=="):
            return True
        return self._entropy(span) > 4.0

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
        base = {k: 0.0 for k in [
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
            # NX-funnel (m)
            "nx_subdomains_per_top_domain", "nx_top_domain_query_ratio",
            # DGA (n)
            "consonant_run_max", "digit_letter_run_max",
        ]}
        # vowel_ratio_min defaults to 1.0 (full vowels = least DGA-like)
        base["vowel_ratio_min"] = 1.0
        return base
