# features/network_features.py
"""
Network feature extractor for credential-based lateral movement.

Computes signals for:
  T1021.001 RDP                     — port 3389 connections
  T1021.002 SMB / admin shares      — port 445 connections
  T1021.004 SSH                     — port 22
  T1021.006 WinRM / PowerShell remoting — ports 5985/5986
  T1047     WMI                     — port 135 + dynamic RPC
  T1059     Shells initiating network connections (cmd / powershell)
  T1218     LOLBin-initiated connections (certutil download, bitsadmin, etc.)

  Plus volume features when bytes data is available from Windows Firewall log.
"""

import ipaddress
from collections import Counter
from typing import Optional

from shared.interfaces import BaseFeatureExtractor
from shared.schemas import NormalizedEvent

# Lateral movement port → feature label
_LATERAL_PORTS = {
    445:  "smb",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm",
    135:  "wmi",
    22:   "ssh",
    23:   "telnet",
    139:  "netbios",
}

# Process basenames that should rarely initiate network connections
_SHELL_PROCS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe",
})

# LOLBins that have legitimate network use but are commonly abused
_LOLBIN_PROCS = frozenset({
    "psexec.exe", "psexesvc.exe", "paexec.exe",
    "wmic.exe", "wmiprvse.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe",
    "net.exe", "net1.exe",
})


class NetworkFeatureExtractor(BaseFeatureExtractor):

    def name(self) -> str:
        return "network"

    def required_event_types(self) -> list[str]:
        return ["network"]

    def extract(self, events: list[NormalizedEvent]) -> dict[str, float]:
        if not events:
            return self._empty()

        n = len(events)

        # ── Per-protocol counts ──────────────────────────────────────────────
        proto_counts: Counter = Counter()
        for e in events:
            label = _LATERAL_PORTS.get(e.dest_port)
            if label:
                proto_counts[label] += 1

        smb_count    = proto_counts.get("smb", 0)
        rdp_count    = proto_counts.get("rdp", 0)
        winrm_count  = proto_counts.get("winrm", 0)
        wmi_count    = proto_counts.get("wmi", 0)
        ssh_count    = proto_counts.get("ssh", 0)
        netbios_cnt  = proto_counts.get("netbios", 0)
        telnet_count = proto_counts.get("telnet", 0)

        total_lateral = (smb_count + rdp_count + winrm_count + wmi_count
                         + ssh_count + netbios_cnt + telnet_count)

        # ── Diversity ────────────────────────────────────────────────────────
        unique_dest_ips   = {e.dest_ip for e in events if e.dest_ip}
        unique_dest_ports = {e.dest_port for e in events if e.dest_port is not None}
        unique_processes  = {self._basename(e.process_name) for e in events if e.process_name}

        # ── Internal vs external destinations ────────────────────────────────
        internal = 0
        external = 0
        for e in events:
            if not e.dest_ip:
                continue
            try:
                ip = ipaddress.ip_address(e.dest_ip)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    internal += 1
                else:
                    external += 1
            except ValueError:
                continue

        internal_to_external = (
            internal / external if external > 0 else float(internal)
        )

        # ── Suspicious source process ────────────────────────────────────────
        shell_initiated = sum(
            1 for e in events
            if self._basename(e.process_name) in _SHELL_PROCS
        )
        lolbin_initiated = sum(
            1 for e in events
            if self._basename(e.process_name) in _LOLBIN_PROCS
        )

        # Shell making lateral movement connections is highest signal
        shell_lateral = sum(
            1 for e in events
            if self._basename(e.process_name) in _SHELL_PROCS
            and e.dest_port in _LATERAL_PORTS
        )

        # ── Connection volume rate ───────────────────────────────────────────
        if len(events) >= 2:
            sorted_ts = sorted(e.timestamp for e in events)
            window_secs = max((sorted_ts[-1] - sorted_ts[0]).total_seconds(), 1.0)
            connections_per_min = (n / window_secs) * 60.0
        else:
            connections_per_min = 0.0

        # ── Bytes (from Windows Firewall log when available) ─────────────────
        total_sent = sum(e.bytes_sent for e in events)
        total_recv = sum(e.bytes_received for e in events)
        max_per_conn = max(
            (e.bytes_sent + e.bytes_received) for e in events
        ) if events else 0

        return {
            # Volume
            "total_connections":             float(n),
            "connections_per_minute":        connections_per_min,
            "total_lateral_count":           float(total_lateral),

            # Per-protocol
            "smb_count":                     float(smb_count),
            "rdp_count":                     float(rdp_count),
            "winrm_count":                   float(winrm_count),
            "wmi_count":                     float(wmi_count),
            "ssh_count":                     float(ssh_count),
            "netbios_count":                 float(netbios_cnt),
            "telnet_count":                  float(telnet_count),

            # Diversity
            "unique_dest_ips":               float(len(unique_dest_ips)),
            "unique_dest_ports":             float(len(unique_dest_ports)),
            "unique_source_processes":       float(len(unique_processes)),

            # Internal vs external
            "internal_connection_count":     float(internal),
            "external_connection_count":     float(external),
            "internal_to_external_ratio":    internal_to_external,

            # Suspicious source process
            "shell_initiated_count":         float(shell_initiated),
            "lolbin_initiated_count":        float(lolbin_initiated),
            "shell_lateral_count":           float(shell_lateral),

            # Bytes
            "total_bytes_sent":              float(total_sent),
            "total_bytes_received":          float(total_recv),
            "max_bytes_per_connection":      float(max_per_conn),
        }

    @staticmethod
    def _basename(path: Optional[str]) -> str:
        if not path:
            return ""
        return path.replace("\\", "/").split("/")[-1].lower()

    def _empty(self) -> dict[str, float]:
        return {k: 0.0 for k in [
            "total_connections", "connections_per_minute", "total_lateral_count",
            "smb_count", "rdp_count", "winrm_count", "wmi_count",
            "ssh_count", "netbios_count", "telnet_count",
            "unique_dest_ips", "unique_dest_ports", "unique_source_processes",
            "internal_connection_count", "external_connection_count",
            "internal_to_external_ratio",
            "shell_initiated_count", "lolbin_initiated_count", "shell_lateral_count",
            "total_bytes_sent", "total_bytes_received", "max_bytes_per_connection",
        ]}
