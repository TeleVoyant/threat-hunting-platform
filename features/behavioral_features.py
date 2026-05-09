# features/behavioral_features.py
"""
Behavioral feature extractor — cross-event correlation patterns.

The single most discriminative signature of credential-based lateral movement
is not any one event but the temporal CHAINING of events:

  1. LSASS access  → authentication      (Pass-the-Hash signature)
  2. Failed auth   → successful auth     (brute-force success)
  3. Authentication → network connection (post-auth lateral connection)
  4. Auth          → process spawn       (creds being used)
  5. Normal logon  → privileged session  (privilege escalation chain)

This extractor counts how often each chain occurs within a short
correlation window (default 5 minutes), with linkage by user where possible.

Operates on ALL event types — it needs cross-type sequencing.
"""

from datetime import timedelta
from typing import Optional

from shared.interfaces import BaseFeatureExtractor
from shared.schemas import NormalizedEvent

# Windows event IDs we correlate on
_AUTH_SUCCESS  = 4624
_AUTH_FAILURE  = 4625
_SPECIAL_LOGON = 4672

# Maximum gap (seconds) between cause and effect for a chain to count
_CHAIN_WINDOW_SEC = 300  # 5 minutes


class BehavioralFeatureExtractor(BaseFeatureExtractor):

    def name(self) -> str:
        return "behavioral"

    def required_event_types(self) -> list[str]:
        # Cross-type extractor — must see the full window
        return ["*"]

    def extract(self, events: list[NormalizedEvent]) -> dict[str, float]:
        if len(events) < 2:
            return self._empty()

        # Sort once; chain checks are forward-looking
        evts = sorted(events, key=lambda e: e.timestamp)

        # ── Bucket events by type / id for O(1) chain detection ──────────────
        lsass_access    = [e for e in evts if e.event_type == "process_access"]
        auth_success    = [e for e in evts if e.windows_event_id == _AUTH_SUCCESS]
        auth_failure    = [e for e in evts if e.windows_event_id == _AUTH_FAILURE]
        network_conns   = [e for e in evts if e.event_type == "network"]
        process_creates = [e for e in evts if e.event_type == "process"]
        special_logons  = [e for e in evts if e.windows_event_id == _SPECIAL_LOGON]

        # ── Chain 1: LSASS access → authentication (PtH signature) ───────────
        # Same user, within window. Highest confidence indicator of cred theft.
        pth_chain = self._count_chain(
            cause_events=lsass_access,
            effect_events=auth_success,
            link_keys=("user",),
        )

        # ── Chain 2: failed auth → successful auth (brute force success) ─────
        bruteforce_success = self._count_chain(
            cause_events=auth_failure,
            effect_events=auth_success,
            link_keys=("user",),
        )

        # ── Chain 3: auth → network connection (post-auth lateral) ───────────
        # Linked by source_ip — same machine that authenticated then reached out
        auth_then_network = self._count_chain(
            cause_events=auth_success,
            effect_events=network_conns,
            link_keys=("source_ip",),
        )

        # ── Chain 4: auth → process spawn (creds in use) ─────────────────────
        auth_then_process = self._count_chain(
            cause_events=auth_success,
            effect_events=process_creates,
            link_keys=("user",),
        )

        # ── Chain 5: normal logon → special privileges (priv escalation) ─────
        priv_escalation = self._count_chain(
            cause_events=auth_success,
            effect_events=special_logons,
            link_keys=("user",),
        )

        # ── Entity diversity ─────────────────────────────────────────────────
        unique_users = len({e.user for e in evts if e.user})
        unique_hosts = len({e.hostname for e in evts if e.hostname})
        unique_procs = len({
            self._basename(e.process_name) for e in evts if e.process_name
        })
        # (host, user) pairs — lateral movement creates many distinct pairs
        host_user_pairs = len({
            (e.hostname, e.user)
            for e in evts if e.hostname and e.user
        })

        # Diversity score — distinct entities relative to volume
        entity_diversity = (unique_users + unique_hosts + unique_procs) / len(evts)

        return {
            # Chain counts (the core indicators)
            "pth_chain_count":            float(pth_chain),
            "bruteforce_success_count":   float(bruteforce_success),
            "auth_then_network_count":    float(auth_then_network),
            "auth_then_process_count":    float(auth_then_process),
            "priv_escalation_chain":      float(priv_escalation),

            # Entity diversity
            "unique_users_overall":       float(unique_users),
            "unique_hosts_overall":       float(unique_hosts),
            "unique_processes_overall":   float(unique_procs),
            "host_user_pair_count":       float(host_user_pairs),
            "entity_diversity_score":     entity_diversity,
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _count_chain(
        self,
        cause_events: list[NormalizedEvent],
        effect_events: list[NormalizedEvent],
        link_keys: tuple[str, ...],
    ) -> int:
        """
        For each cause event, count one match if some effect event happens
        within _CHAIN_WINDOW_SEC AFTER it AND shares all link_keys.
        Each cause counts at most once — this prevents one runaway effect
        burst from inflating the count.

        Linkage rule: if either side is missing the linkage field, fall back
        to time-only correlation (don't filter out the link).
        """
        if not cause_events or not effect_events:
            return 0

        window = timedelta(seconds=_CHAIN_WINDOW_SEC)
        count = 0

        for cause in cause_events:
            for effect in effect_events:
                if effect.timestamp <= cause.timestamp:
                    continue
                if effect.timestamp - cause.timestamp > window:
                    continue
                if all(self._linked(cause, effect, k) for k in link_keys):
                    count += 1
                    break  # one chain per cause

        return count

    @staticmethod
    def _linked(a: NormalizedEvent, b: NormalizedEvent, key: str) -> bool:
        va = getattr(a, key, None)
        vb = getattr(b, key, None)
        # If either side lacks the linkage field, fall through (time-only correlation)
        if va is None or vb is None:
            return True
        return va == vb

    @staticmethod
    def _basename(path: Optional[str]) -> str:
        if not path:
            return ""
        return path.replace("\\", "/").split("/")[-1].lower()

    def _empty(self) -> dict[str, float]:
        return {k: 0.0 for k in [
            "pth_chain_count", "bruteforce_success_count",
            "auth_then_network_count", "auth_then_process_count",
            "priv_escalation_chain",
            "unique_users_overall", "unique_hosts_overall",
            "unique_processes_overall", "host_user_pair_count",
            "entity_diversity_score",
        ]}
