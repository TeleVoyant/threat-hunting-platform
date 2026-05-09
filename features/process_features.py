# features/process_features.py
"""
Process feature extractor for credential-based lateral movement.

Computes signals for:
  T1003     Credential dumping  — mimikatz, procdump, sekurlsa, LSASS access
  T1059     Command interpreters — PowerShell -EncodedCommand, IEX, downloads
  T1218     Signed binary proxy — rundll32, regsvr32, mshta, certutil, bitsadmin
  T1021.002 SMB / admin shares  — psexec, paexec, smbexec
  T1047     WMI lateral movement — wmic, wmiprvse
  T1055     Process injection   — CreateRemoteThread, process tampering
  T1570     Lateral tool transfer — file drops in user-writable paths
"""

import re
from collections import Counter
from typing import Optional

from shared.interfaces import BaseFeatureExtractor
from shared.schemas import NormalizedEvent

# ── Tool / binary catalogues ────────────────────────────────────────────────

# Substring matches in image path or command line — credential dumping tools
_CRED_TOOLS = (
    "mimikatz", "mimilove", "wce.exe", "procdump", "sekurlsa",
    "kerberoast", "rubeus", "lazagne", "sharpkatz", "safetykatz",
    "pypykatz", "creddump", "ntdsutil",
)

# LOLBin process basenames — legitimate system tools abused for attacks
_LOLBINS = frozenset({
    "psexec.exe", "psexesvc.exe", "paexec.exe",     # SMB-based remote exec
    "wmic.exe", "wmiprvse.exe",                     # WMI
    "mshta.exe", "rundll32.exe", "regsvr32.exe",    # signed binary proxies
    "certutil.exe", "bitsadmin.exe",                # download tools
    "wscript.exe", "cscript.exe",                   # script hosts
    "at.exe", "schtasks.exe",                       # scheduled task creation
    "sc.exe", "net.exe", "net1.exe",                # service/share commands
    "esentutl.exe",                                 # NTDS.dit copy via VSS
    "vssadmin.exe",                                 # Volume Shadow Copy
    "dnscmd.exe",                                   # DNS admin
})

# PowerShell encoded command pattern: -e / -enc / -encodedcommand <base64>
_ENCODED_CMD_RE = re.compile(
    r"-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}",
    re.IGNORECASE,
)

# Network download patterns inside command lines
_DOWNLOAD_RE = re.compile(
    r"\b(downloadstring|downloadfile|downloaddata|invoke-webrequest|"
    r"net\.webclient|wget|curl|bitstransfer|start-bitstransfer|iex)\b",
    re.IGNORECASE,
)

# AMSI bypass markers
_AMSI_BYPASS_RE = re.compile(
    r"amsi(initfailed|utils|context|scanbuffer)",
    re.IGNORECASE,
)

# Suspicious parent-child chains
_OFFICE_PROCS  = frozenset({"winword.exe", "excel.exe", "powerpnt.exe",
                            "outlook.exe", "msaccess.exe"})
_BROWSER_PROCS = frozenset({"chrome.exe", "msedge.exe", "firefox.exe",
                            "iexplore.exe", "brave.exe"})
_SHELL_PROCS   = frozenset({"cmd.exe", "powershell.exe", "pwsh.exe",
                            "wscript.exe", "cscript.exe"})

# Named-pipe signatures used by lateral movement frameworks
_PIPE_PATTERNS = re.compile(
    r"(\\PSEXECSVC|\\psexec|\\msse-|\\status_|\\msagent_|\\dsername|postex_)",
    re.IGNORECASE,
)


class ProcessFeatureExtractor(BaseFeatureExtractor):

    def name(self) -> str:
        return "process"

    def required_event_types(self) -> list[str]:
        return [
            "process",         # Sysmon EID 1
            "process_access",  # Sysmon EID 10  (LSASS dumping)
            "image_load",      # Sysmon EID 7   (credential DLL loads)
            "remote_thread",   # Sysmon EID 8   (process injection)
            "process_tamper",  # Sysmon EID 25
            "pipe",            # Sysmon EID 17/18
            "file_create",     # Sysmon EID 11
        ]

    def extract(self, events: list[NormalizedEvent]) -> dict[str, float]:
        if not events:
            return self._empty()

        # ── Bucket by event type ─────────────────────────────────────────────
        proc_create   = [e for e in events if e.event_type == "process"]
        lsass_access  = [e for e in events if e.event_type == "process_access"]
        image_load    = [e for e in events if e.event_type == "image_load"]
        remote_thread = [e for e in events if e.event_type == "remote_thread"]
        proc_tamper   = [e for e in events if e.event_type == "process_tamper"]
        pipe_evts     = [e for e in events if e.event_type == "pipe"]
        file_create   = [e for e in events if e.event_type == "file_create"]

        # ── Credential-dumping indicators ────────────────────────────────────
        cred_tool_count = sum(
            1 for e in proc_create
            if self._matches_any(e, _CRED_TOOLS)
        )

        # ── LOLBin counts (per-binary so XGBoost can split on each) ──────────
        lolbin_counts: Counter = Counter()
        for e in proc_create:
            base = self._basename(e.process_name)
            if base in _LOLBINS:
                lolbin_counts[base] += 1
        total_lolbin = sum(lolbin_counts.values())

        # ── PowerShell abuse ─────────────────────────────────────────────────
        ps_events = [
            e for e in proc_create
            if self._basename(e.process_name) in {"powershell.exe", "pwsh.exe"}
        ]
        encoded_cmd_count = sum(
            1 for e in ps_events
            if e.command_line and _ENCODED_CMD_RE.search(e.command_line)
        )
        download_count = sum(
            1 for e in ps_events
            if e.command_line and _DOWNLOAD_RE.search(e.command_line)
        )
        amsi_count = sum(
            1 for e in ps_events
            if e.command_line and _AMSI_BYPASS_RE.search(e.command_line)
        )

        # ── Suspicious parent → child chains ─────────────────────────────────
        office_to_shell = sum(
            1 for e in proc_create
            if self._basename(e.parent_process) in _OFFICE_PROCS
            and self._basename(e.process_name) in _SHELL_PROCS
        )
        browser_to_shell = sum(
            1 for e in proc_create
            if self._basename(e.parent_process) in _BROWSER_PROCS
            and self._basename(e.process_name) in _SHELL_PROCS
        )

        # ── Named-pipe lateral movement (Sysmon EID 17/18) ───────────────────
        pipe_attack_count = sum(
            1 for e in pipe_evts
            if self._raw_pipename_matches(e.raw)
        )

        # ── File staging (T1074) ─────────────────────────────────────────────
        archive_drops = sum(
            1 for e in file_create
            if self._target_filename_matches(e.raw, r"\.(zip|7z|rar|tar|gz)$")
        )
        user_exe_drops = sum(
            1 for e in file_create
            if self._target_filename_matches(e.raw, r"^c:\\users\\.*\.(exe|dll|ps1|vbs|hta|bat)$")
        )

        # ── Process diversity ────────────────────────────────────────────────
        unique_images  = {self._basename(e.process_name) for e in proc_create if e.process_name}
        unique_parents = {self._basename(e.parent_process) for e in proc_create if e.parent_process}

        return {
            # Volume
            "total_process_events":   float(len(proc_create)),

            # Credential dumping
            "credential_tool_count":  float(cred_tool_count),
            "lsass_access_count":     float(len(lsass_access)),
            "image_load_count":       float(len(image_load)),
            "remote_thread_count":    float(len(remote_thread)),
            "process_tamper_count":   float(len(proc_tamper)),

            # LOLBins (per-binary, plus aggregate)
            "psexec_count":           float(lolbin_counts.get("psexec.exe", 0) +
                                            lolbin_counts.get("psexesvc.exe", 0) +
                                            lolbin_counts.get("paexec.exe", 0)),
            "wmic_count":             float(lolbin_counts.get("wmic.exe", 0) +
                                            lolbin_counts.get("wmiprvse.exe", 0)),
            "mshta_count":            float(lolbin_counts.get("mshta.exe", 0)),
            "rundll32_count":         float(lolbin_counts.get("rundll32.exe", 0)),
            "regsvr32_count":         float(lolbin_counts.get("regsvr32.exe", 0)),
            "certutil_count":         float(lolbin_counts.get("certutil.exe", 0)),
            "bitsadmin_count":        float(lolbin_counts.get("bitsadmin.exe", 0)),
            "schtasks_count":         float(lolbin_counts.get("schtasks.exe", 0) +
                                            lolbin_counts.get("at.exe", 0)),
            "esentutl_count":         float(lolbin_counts.get("esentutl.exe", 0)),
            "total_lolbin_count":     float(total_lolbin),

            # PowerShell abuse
            "powershell_count":       float(len(ps_events)),
            "encoded_command_count":  float(encoded_cmd_count),
            "download_command_count": float(download_count),
            "amsi_bypass_count":      float(amsi_count),

            # Parent-child chains
            "office_to_shell_count":  float(office_to_shell),
            "browser_to_shell_count": float(browser_to_shell),

            # Named pipes
            "pipe_event_count":       float(len(pipe_evts)),
            "pipe_attack_count":      float(pipe_attack_count),

            # File staging
            "archive_drop_count":     float(archive_drops),
            "user_exe_drop_count":    float(user_exe_drops),
            "file_create_count":      float(len(file_create)),

            # Diversity
            "unique_image_count":     float(len(unique_images)),
            "unique_parent_count":    float(len(unique_parents)),
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _basename(path: Optional[str]) -> str:
        if not path:
            return ""
        return path.replace("\\", "/").split("/")[-1].lower()

    def _matches_any(self, event: NormalizedEvent, patterns: tuple[str, ...]) -> bool:
        haystack = " ".join(filter(None, [
            event.process_name or "",
            event.command_line or "",
            event.parent_process or "",
        ])).lower()
        return any(p in haystack for p in patterns)

    @staticmethod
    def _raw_pipename_matches(raw: dict) -> bool:
        """Sysmon EID 17/18 store the pipe name in eventdata.pipeName."""
        if not raw:
            return False
        evt = raw.get("data", {}).get("win", {}).get("eventdata", {})
        pipe = evt.get("pipeName") or evt.get("PipeName") or ""
        return bool(pipe and _PIPE_PATTERNS.search(pipe))

    @staticmethod
    def _target_filename_matches(raw: dict, pattern: str) -> bool:
        """Sysmon EID 11 stores the path in eventdata.targetFilename."""
        if not raw:
            return False
        evt = raw.get("data", {}).get("win", {}).get("eventdata", {})
        target = (evt.get("targetFilename") or evt.get("TargetFilename") or "").lower()
        return bool(target and re.search(pattern, target, re.IGNORECASE))

    def _empty(self) -> dict[str, float]:
        return {k: 0.0 for k in [
            # Volume
            "total_process_events",
            # Credential dumping
            "credential_tool_count", "lsass_access_count", "image_load_count",
            "remote_thread_count", "process_tamper_count",
            # LOLBins
            "psexec_count", "wmic_count", "mshta_count",
            "rundll32_count", "regsvr32_count", "certutil_count",
            "bitsadmin_count", "schtasks_count", "esentutl_count",
            "total_lolbin_count",
            # PowerShell
            "powershell_count", "encoded_command_count",
            "download_command_count", "amsi_bypass_count",
            # Chains
            "office_to_shell_count", "browser_to_shell_count",
            # Pipes
            "pipe_event_count", "pipe_attack_count",
            # File staging
            "archive_drop_count", "user_exe_drop_count", "file_create_count",
            # Diversity
            "unique_image_count", "unique_parent_count",
        ]}
