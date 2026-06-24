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

import re
from collections import Counter
from typing import Optional

from shared.interfaces import BaseFeatureExtractor
from shared.schemas import NormalizedEvent

# Process basenames associated with credential abuse / lateral movement
# tooling. Matched case-insensitively against `process_name` on process or
# process_access events that share the auth window.
_PSEXEC_PROCS  = frozenset({"psexec.exe", "psexec64.exe", "paexec.exe"})
_WMIC_PROCS    = frozenset({"wmic.exe", "wmiprvse.exe"})
_WINRM_PROCS   = frozenset({"winrshost.exe", "wsmprovhost.exe"})
_SCHTASK_PROCS = frozenset({"schtasks.exe", "at.exe"})
_PWSH_PROCS    = frozenset({"powershell.exe", "pwsh.exe"})
_LSASS_NAME    = "lsass.exe"

# PowerShell `-EncodedCommand` flag — short or long form (case-insensitive).
_PWSH_ENC_RE = re.compile(r"(?:\s|^)-(?:e|en|enc|enco|encod|encode|encodedcommand)(?:\s|=)", re.IGNORECASE)

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

    def __init__(self, window_minutes: int = 5):
        # Instance attribute so all callers can pass event_window_minutes from
        # PlatformConfig instead of relying on a hardcoded class constant.
        # Default preserves the previous behaviour when no arg is supplied.
        self.WINDOW_SECONDS = window_minutes * 60

    def name(self) -> str:
        return "auth"

    def required_event_types(self) -> list[str]:
        # Process / process_access events are joined into the auth window to
        # surface lateral-movement tooling signals (psexec, wmic, lsass dump
        # attempts, encoded PowerShell). See (k).
        return [
            "authentication", "account_management",
            "process", "process_access",
        ]

    def extract(self, events: list[NormalizedEvent]) -> dict[str, float]:
        # Same canonical-order discipline as the DNS extractor: build the
        # empty schema first, overlay computed values. Guarantees the dict
        # key order is identical across every window so the trainer's
        # schema-drift check (extract_training_matrix) never trips.
        result = self._empty()
        if not events:
            return result

        # Split by event_type so the auth-only counters don't get polluted by
        # process events that ride the same window.
        auth_events = [
            e for e in events
            if e.event_type in ("authentication", "account_management")
        ]
        proc_events = [
            e for e in events
            if e.event_type in ("process", "process_access")
        ]

        n = len(auth_events)
        eid_counts = Counter(e.windows_event_id for e in auth_events)

        # ── Volume ───────────────────────────────────────────────────────────
        success_count = eid_counts.get(_AUTH_SUCCESS, 0)
        failure_count = eid_counts.get(_AUTH_FAILURE, 0)
        total_logons  = success_count + failure_count

        # ── Logon type analysis (only meaningful on 4624) ────────────────────
        ltype_counts = Counter(
            e.logon_type for e in auth_events
            if e.windows_event_id == _AUTH_SUCCESS and e.logon_type is not None
        )
        net_logons = ltype_counts.get(_LOGON_NETWORK, 0)

        # ── Brute-force / password-spray signal: failures per user ───────────
        per_user_failures = Counter(
            e.user for e in auth_events
            if e.windows_event_id == _AUTH_FAILURE and e.user
        )
        max_fail_per_user = max(per_user_failures.values()) if per_user_failures else 0

        # Same source IP attacking many distinct user accounts (password spray)
        per_source_failed_users = {}
        for e in auth_events:
            if e.windows_event_id == _AUTH_FAILURE and e.source_ip and e.user:
                per_source_failed_users.setdefault(e.source_ip, set()).add(e.user)
        max_users_per_source = max(
            (len(s) for s in per_source_failed_users.values()), default=0
        )

        # ── Privilege escalation ─────────────────────────────────────────────
        priv_users = {
            e.user for e in auth_events
            if e.windows_event_id == _SPECIAL_LOGON and e.user
        }

        # ── Spread across hosts/users/sources ────────────────────────────────
        # hostname = the agent that captured the event = the TARGET host being
        # authenticated to. Cross-agent aggregation gives lateral movement spread.
        unique_target_hosts = {e.hostname for e in auth_events if e.hostname}
        unique_users        = {e.user for e in auth_events if e.user}
        unique_source_ips   = {
            e.source_ip for e in auth_events
            if e.source_ip and e.source_ip not in ("0.0.0.0", "-", "::1", "127.0.0.1")
        }

        # Lateral velocity: distinct target hosts touched per minute, computed
        # against the FIXED analytic window (not the empirical event span).
        # The old span-based denominator clipped to 1s, so any short burst
        # produced inflated 60×hosts velocity — model couldn't generalise.
        lateral_velocity = (len(unique_target_hosts) / self.WINDOW_SECONDS) * 60.0

        # ── Per-user lateral spread (one user touching many hosts) ───────────
        per_user_hosts = {}
        for e in auth_events:
            if e.windows_event_id == _AUTH_SUCCESS and e.user and e.hostname:
                per_user_hosts.setdefault(e.user, set()).add(e.hostname)
        max_hosts_per_user = max(
            (len(s) for s in per_user_hosts.values()), default=0
        )

        # ── Success-after-failure burst (o) — credential stuffing / PtH ─────
        # Per source_ip, did we see a 4625 followed by a 4624 within window?
        # 1 = yes (highest-signal lateral pattern), 0 = no. Also captures the
        # latency: time_to_first_success in seconds (smaller = more automated).
        success_after_fail = 0
        time_to_first_success = 0.0
        by_source: dict[str, list] = {}
        for e in sorted(auth_events, key=lambda x: x.timestamp):
            if not e.source_ip:
                continue
            if e.windows_event_id in (_AUTH_FAILURE, _AUTH_SUCCESS):
                by_source.setdefault(e.source_ip, []).append(e)
        for src, evts in by_source.items():
            first_fail_ts = None
            for ev in evts:
                if ev.windows_event_id == _AUTH_FAILURE and first_fail_ts is None:
                    first_fail_ts = ev.timestamp
                elif ev.windows_event_id == _AUTH_SUCCESS and first_fail_ts is not None:
                    success_after_fail = 1
                    time_to_first_success = max(
                        (ev.timestamp - first_fail_ts).total_seconds(), 0.0
                    )
                    break
            if success_after_fail:
                break

        # ── Time-of-day signals (l-lite). Model learns its own baseline ────
        # of when an entity normally authenticates. Off-hours auth is
        # disproportionately interactive — interactive_offhours is more
        # actionable than raw hour of day.
        offhours_total = 0
        offhours_interactive = 0
        for e in auth_events:
            if e.windows_event_id != _AUTH_SUCCESS:
                continue
            hour = e.timestamp.hour  # UTC; analyst trains in same TZ
            if hour < 6 or hour >= 22:  # 22:00–06:00 considered off-hours
                offhours_total += 1
                if e.logon_type in (_LOGON_INTERACTIVE, _LOGON_REMOTE_INTERACTIVE):
                    offhours_interactive += 1

        # ── Process-context join (k) — lateral movement tooling ─────────────
        proc_basenames = [
            self._proc_basename(e.process_name) for e in proc_events if e.process_name
        ]
        psexec_count   = sum(1 for p in proc_basenames if p in _PSEXEC_PROCS)
        wmic_count     = sum(1 for p in proc_basenames if p in _WMIC_PROCS)
        winrm_count    = sum(1 for p in proc_basenames if p in _WINRM_PROCS)
        schtasks_count = sum(1 for p in proc_basenames if p in _SCHTASK_PROCS)

        # Encoded PowerShell — a single instance is suspicious; we cap at 5
        # so the feature stays in a sane range for the model.
        pwsh_encoded_count = 0
        for e in proc_events:
            if not e.command_line:
                continue
            base = self._proc_basename(e.process_name)
            if base in _PWSH_PROCS and _PWSH_ENC_RE.search(e.command_line):
                pwsh_encoded_count += 1
        pwsh_encoded_count = min(pwsh_encoded_count, 5)

        # LSASS access — process_access events targeting lsass.exe are the
        # signature of credential dumping (Mimikatz, lsassy, ProcDump).
        lsass_access_count = 0
        for e in proc_events:
            if e.event_type != "process_access":
                continue
            # The target of process_access is typically captured in raw[].
            target = (e.raw or {}).get("data", {}).get("win", {}) \
                .get("eventdata", {}).get("targetImage", "") if isinstance(e.raw, dict) else ""
            if self._proc_basename(target) == _LSASS_NAME:
                lsass_access_count += 1

        result.update({
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

            # Success-after-failure (o)
            "success_after_failures":         float(success_after_fail),
            "time_to_first_success_secs":     float(time_to_first_success),

            # Time-of-day (l-lite)
            "offhours_logon_count":           float(offhours_total),
            "offhours_interactive_count":     float(offhours_interactive),

            # Process-context (k) — lateral movement tooling
            "psexec_invocations":             float(psexec_count),
            "wmic_invocations":               float(wmic_count),
            "winrm_invocations":              float(winrm_count),
            "schtasks_invocations":           float(schtasks_count),
            "powershell_encoded_count":       float(pwsh_encoded_count),
            "lsass_access_count":             float(lsass_access_count),
        })
        return result

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
            # Success-after-failure (o)
            "success_after_failures", "time_to_first_success_secs",
            # Time-of-day (l-lite)
            "offhours_logon_count", "offhours_interactive_count",
            # Process-context (k)
            "psexec_invocations", "wmic_invocations", "winrm_invocations",
            "schtasks_invocations", "powershell_encoded_count", "lsass_access_count",
        ]}

    @staticmethod
    def _proc_basename(path: Optional[str]) -> str:
        if not path:
            return ""
        return path.replace("\\", "/").rsplit("/", 1)[-1].lower()
