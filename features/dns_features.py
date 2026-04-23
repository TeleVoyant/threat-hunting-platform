# features/dns_features.py
import math
from collections import Counter
from shared.interfaces import BaseFeatureExtractor
from shared.schemas import NormalizedEvent


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
            "query_count": float(len(queries)),
            "avg_query_length": sum(len(q) for q in queries) / len(queries),
            "max_query_length": float(max(len(q) for q in queries)),
            "avg_subdomain_depth": sum(q.count(".") for q in queries) / len(queries),
            "avg_entropy": sum(self._shannon_entropy(q) for q in queries)
            / len(queries),
            "max_entropy": max(self._shannon_entropy(q) for q in queries),
            "unique_subdomain_ratio": len(set(queries)) / len(queries),
            "txt_record_ratio": sum(1 for e in events if e.dns_query_type == "TXT")
            / len(events),
            "null_record_ratio": sum(1 for e in events if e.dns_query_type == "NULL")
            / len(events),
            "avg_response_size": sum(e.bytes_received for e in events) / len(events),
            "base64_pattern_count": sum(1 for q in queries if self._has_base64(q)),
            "hex_pattern_count": sum(1 for q in queries if self._has_hex(q)),
            "numeric_ratio": sum(self._numeric_ratio(q) for q in queries)
            / len(queries),
            "unique_base_domains": float(
                len(set(self._base_domain(q) for q in queries))
            ),
        }

    def _shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def _has_base64(self, query: str) -> bool:
        import re

        return bool(re.search(r"[A-Za-z0-9+/]{20,}={0,2}", query))

    def _has_hex(self, query: str) -> bool:
        import re

        return bool(re.search(r"[0-9a-f]{16,}", query.lower()))

    def _numeric_ratio(self, query: str) -> float:
        if not query:
            return 0.0
        return sum(1 for c in query if c.isdigit()) / len(query)

    def _base_domain(self, query: str) -> str:
        parts = query.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else query

    def _empty_features(self) -> dict[str, float]:
        return {
            k: 0.0
            for k in [
                "query_count",
                "avg_query_length",
                "max_query_length",
                "avg_subdomain_depth",
                "avg_entropy",
                "max_entropy",
                "unique_subdomain_ratio",
                "txt_record_ratio",
                "null_record_ratio",
                "avg_response_size",
                "base64_pattern_count",
                "hex_pattern_count",
                "numeric_ratio",
                "unique_base_domains",
            ]
        }
