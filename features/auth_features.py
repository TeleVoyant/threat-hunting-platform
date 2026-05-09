# features/auth_features.py
"""
Authentication feature extractor for credential-based lateral movement.

Computes signals for the MITRE ATT&CK techniques:
  T1110     Brute force            — high 4625 failure rate, single user spray
  T1078     Valid accounts         — abnormal logon patterns, off-hours auth
  T1550.002 Pass-the-Hash          — explicit cred logons (4648), NTLM bursts (4776)
  T1550.003 Pass-the-Ticket        — Kerberos TGS volume (4769) without TGT (4768)
  T1021     Remote services        — type-3 logons across many target hosts
  T1136     Create account         — 4720/4722/4724/4725/4726/4738
  T1098     Account manipulation   — privilege changes, group additions
"""

from collections import Counter

from shared.interfaces import BaseFeatureExtractor
from shared.schemas import NormalizedEvent

# ── Windows Security event IDs ──────────────────────────────────────────────
_AUTH_SUCCESS    = 4624
_AUTH_FAILURE    = 4625
_EXPLICIT_CRED   = 4648  # T1550.002 (Pass-the-Hash)
_SPECIAL_LOGON   = 4672  # privileged session granted
_KERBEROS_TGT    = 4768  # initial Kerberos ticket
_KERBEROS_TGS    = 4769  # service ticket (Kerberoasting if many)
_NTLM_AUTH       = 4776  # NTLM credential validation

# Account management (persistence indicators)
_ACCT_CREATE     = 4720
_ACCT_ENABLE     = 4722
_ACCT_PASSRESET  = 4724
_ACCT_DISABLE    = 4725
_ACCT_DELETE     = 4726
_ACCT_CHANGE     = 4738

# ── Windows logon types ─────────────────────────────────────────────────────
_LOGON_INTERACTIVE        = 2
_LOGON_NETWORK            = 3   # primary lateral-movement signal (SMB, WMI, WinRM)
_LOGON_SERVICE            = 5
_LOGON_NETWORK_CLEARTEXT  = 8   # plaintext over network — never legitimate
_LOGON_REMOTE_INTERACTIVE = 10  # RDP


class AuthFeatureExtractor(BaseFeatureExtractor):

    def name(self) -> str:
        return "auth"

    def required_event_types(self) -> list[str]:
        return ["authentication", "account_management"]

    def extract(self, events: list[NormalizedEvent]) -> dict[str, float]:
        if not events:
            return self._empty()

        n = len(events)
        eid_counts = Counter(e.windows_event_id for e in events)

        # ── Volume ───────────────────────────────────────────────────────────
        success_count = eid_counts.get(_AUTH_SUCCESS, 0)
        failure_count = eid_counts.get(_AUTH_FAILURE, 0)
        total_logons  = success_count + failure_count

        # ── Logon type analysis (only meaningful on 4624) ────────────────────
        ltype_counts = Counter(
            e.logon_type for e in events
            if e.windows_event_id == _AUTH_SUCCESS and e.logon_type is not None
        )
        net_logons = ltype_counts.get(_LOGON_NETWORK, 0)

        # ── Brute-force / password-spray signal: failures per user ───────────
        per_user_failures = Counter(
            e.user for e in events
            if e.windows_event_id == _AUTH_FAILURE and e.user
        )
        max_fail_per_user = max(per_user_failures.values()) if per_user_failures else 0

        # Same source IP attacking many distinct user accounts (password spray)
        per_source_failed_users = {}
        for e in events:
            if e.windows_event_id == _AUTH_FAILURE and e.source_ip and e.user:
                per_source_failed_users.setdefault(e.source_ip, set()).add(e.user)
        max_users_per_source = max(
            (len(s) for s in per_source_failed_users.values()), default=0
        )

        # ── Privilege escalation ─────────────────────────────────────────────
        priv_users = {
            e.user for e in events
            if e.windows_event_id == _SPECIAL_LOGON and e.user
        }

        # ── Spread across hosts/users/sources ────────────────────────────────
        # hostname = the agent that captured the event = the TARGET host being
        # authenticated to. Cross-agent aggregation gives lateral movement spread.
        unique_target_hosts = {e.hostname for e in events if e.hostname}
        unique_users        = {e.user for e in events if e.user}
        unique_source_ips   = {
            e.source_ip for e in events
            if e.source_ip and e.source_ip not in ("0.0.0.0", "-", "::1", "127.0.0.1")
        }

        # Lateral velocity: distinct target hosts touched per minute
        if len(events) >= 2:
            sorted_ts = sorted(e.timestamp for e in events)
            window_secs = max((sorted_ts[-1] - sorted_ts[0]).total_seconds(), 1.0)
            lateral_velocity = (len(unique_target_hosts) / window_secs) * 60.0
        else:
            lateral_velocity = 0.0

        # ── Per-user lateral spread (one user touching many hosts) ───────────
        per_user_hosts = {}
        for e in events:
            if e.windows_event_id == _AUTH_SUCCESS and e.user and e.hostname:
                per_user_hosts.setdefault(e.user, set()).add(e.hostname)
        max_hosts_per_user = max(
            (len(s) for s in per_user_hosts.values()), default=0
        )

        return {
            # Volume
            "total_auth_events":              float(n),
            "successful_logon_count":         float(success_count),
            "failed_logon_count":             float(failure_count),
            "failed_logon_ratio":             (failure_count / total_logons) if total_logons else 0.0,

            # Logon type distribution
            "network_logon_count":            float(net_logons),
            "interactive_logon_count":        float(ltype_counts.get(_LOGON_INTERACTIVE, 0)),
            "remote_interactive_logon_count": float(ltype_counts.get(_LOGON_REMOTE_INTERACTIVE, 0)),
            "service_logon_count":            float(ltype_counts.get(_LOGON_SERVICE, 0)),
            "cleartext_logon_count":          float(ltype_counts.get(_LOGON_NETWORK_CLEARTEXT, 0)),
            "network_logon_ratio":            (net_logons / success_count) if success_count else 0.0,

            # PtH / PtT signature
            "explicit_credential_count":      float(eid_counts.get(_EXPLICIT_CRED, 0)),
            "ntlm_count":                     float(eid_counts.get(_NTLM_AUTH, 0)),
            "kerberos_tgt_count":             float(eid_counts.get(_KERBEROS_TGT, 0)),
            "kerberos_tgs_count":             float(eid_counts.get(_KERBEROS_TGS, 0)),

            # Privilege
            "special_logon_count":            float(eid_counts.get(_SPECIAL_LOGON, 0)),
            "unique_privileged_users":        float(len(priv_users)),

            # Spread (lateral movement signal)
            "unique_users":                   float(len(unique_users)),
            "unique_target_hosts":            float(len(unique_target_hosts)),
            "unique_source_ips":              float(len(unique_source_ips)),
            "lateral_velocity_per_min":       lateral_velocity,
            "max_hosts_per_user":             float(max_hosts_per_user),

            # Brute force / password spray
            "max_failures_per_user":          float(max_fail_per_user),
            "unique_failed_users":            float(len(per_user_failures)),
            "max_users_per_source":           float(max_users_per_source),

            # Account manipulation (T1136 persistence)
            "account_created_count":          float(eid_counts.get(_ACCT_CREATE, 0)),
            "account_enabled_count":          float(eid_counts.get(_ACCT_ENABLE, 0)),
            "password_reset_count":           float(eid_counts.get(_ACCT_PASSRESET, 0)),
            "account_disabled_count":         float(eid_counts.get(_ACCT_DISABLE, 0)),
            "account_deleted_count":          float(eid_counts.get(_ACCT_DELETE, 0)),
            "account_changed_count":          float(eid_counts.get(_ACCT_CHANGE, 0)),
        }

    def _empty(self) -> dict[str, float]:
        return {k: 0.0 for k in [
            # Volume
            "total_auth_events", "successful_logon_count", "failed_logon_count",
            "failed_logon_ratio",
            # Logon type
            "network_logon_count", "interactive_logon_count",
            "remote_interactive_logon_count", "service_logon_count",
            "cleartext_logon_count", "network_logon_ratio",
            # PtH/PtT
            "explicit_credential_count", "ntlm_count",
            "kerberos_tgt_count", "kerberos_tgs_count",
            # Privilege
            "special_logon_count", "unique_privileged_users",
            # Spread
            "unique_users", "unique_target_hosts", "unique_source_ips",
            "lateral_velocity_per_min", "max_hosts_per_user",
            # Brute force
            "max_failures_per_user", "unique_failed_users", "max_users_per_source",
            # Account manipulation
            "account_created_count", "account_enabled_count",
            "password_reset_count", "account_disabled_count",
            "account_deleted_count", "account_changed_count",
        ]}
