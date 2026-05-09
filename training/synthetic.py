# training/synthetic.py
"""
Synthetic event generator for bootstrapping detector models.

Produces realistic NormalizedEvent batches with two attack types interspersed
in normal background traffic, plus a per-event ground-truth label so that
trainer.py can window-and-label downstream.

Use this BEFORE you have real lab attack captures, so the platform has
trained models for the demo. Once you have real labeled data, swap this for
training.event_loader and the rest of the pipeline is unchanged.

Output: list[(NormalizedEvent, label_int)]   where label = 1 if event is part
of an attack scenario, 0 otherwise.

Coverage matches what the feature extractors look for:
  Lateral movement scenario:
    - 4625 brute force burst from one source IP against one user
    - 4624 success after a few failures
    - 4672 special privileges granted
    - Sysmon EID 10 LSASS access (mimikatz-like image path)
    - Sysmon EID 1 PowerShell with -EncodedCommand
    - Sysmon EID 3 to ports 445/3389/135 against 3+ internal hosts

  DNS exfiltration scenario:
    - Sysmon EID 22 with high-entropy long subdomains under one base domain
    - Mix of TXT and NULL response types
    - Small fraction of NXDOMAIN
    - Source process is a non-browser binary
    - DNS Client EID 3008 events with low TTL
"""

import random
import string
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional

from shared.schemas import NormalizedEvent


# ── Constants for normal-traffic shape ──────────────────────────────────────

_BENIGN_DOMAINS = [
    "windowsupdate.com", "microsoft.com", "office.com", "office365.com",
    "google.com", "googleapis.com", "github.com", "github.io",
    "live.com", "msedge.net", "mozilla.org",
]
_BENIGN_PROCESSES = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
]
_BENIGN_USERS = ["alice", "bob", "carol", "dave", "eve.legit"]


# ── Helpers ─────────────────────────────────────────────────────────────────

def _now(seed_ts: datetime, jitter_sec: int = 0) -> datetime:
    return seed_ts + timedelta(seconds=jitter_sec)


def _rand_subdomain(length: int, charset: str = string.ascii_lowercase + string.digits) -> str:
    """Generate a random subdomain of `length` chars from `charset`."""
    return "".join(random.choices(charset, k=length))


def _make(
    event_type: str,
    timestamp: datetime,
    hostname: str,
    *,
    eid: Optional[int] = None,
    source_ip: str = "192.168.1.50",
    dest_ip: Optional[str] = None,
    dest_port: Optional[int] = None,
    user: Optional[str] = None,
    logon_type: Optional[int] = None,
    process_name: Optional[str] = None,
    parent_process: Optional[str] = None,
    command_line: Optional[str] = None,
    dns_query: Optional[str] = None,
    dns_query_type: Optional[str] = None,
    dns_response_code: Optional[str] = None,
    dns_query_results: Optional[str] = None,
    dns_ttl: Optional[int] = None,
    bytes_sent: int = 0,
    bytes_received: int = 0,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp,
        source_ip=source_ip,
        dest_ip=dest_ip,
        dest_port=dest_port,
        user=user,
        hostname=hostname,
        event_type=event_type,
        windows_event_id=eid,
        logon_type=logon_type,
        process_name=process_name,
        parent_process=parent_process,
        command_line=command_line,
        dns_query=dns_query,
        dns_query_type=dns_query_type,
        dns_response_code=dns_response_code,
        dns_query_results=dns_query_results,
        dns_ttl=dns_ttl,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
    )


# ── Normal background traffic ───────────────────────────────────────────────

def generate_normal_minute(
    base_ts: datetime, hostname: str
) -> Iterator[tuple[NormalizedEvent, int]]:
    """
    One minute of background traffic for one host. Returns ~10–30 events.
    Each yielded as (event, label=0).
    """
    # 1–5 successful interactive logons per minute (LOW for active hours)
    for _ in range(random.randint(0, 2)):
        yield _make(
            "authentication", _now(base_ts, random.randint(0, 59)),
            hostname=hostname, eid=4624,
            user=random.choice(_BENIGN_USERS), logon_type=2,
            source_ip="0.0.0.0",   # local interactive
        ), 0

    # 0–1 failed logons (typos)
    if random.random() < 0.3:
        yield _make(
            "authentication", _now(base_ts, random.randint(0, 59)),
            hostname=hostname, eid=4625,
            user=random.choice(_BENIGN_USERS), logon_type=2,
        ), 0

    # 5–15 DNS queries to common domains
    for _ in range(random.randint(5, 15)):
        domain = random.choice(_BENIGN_DOMAINS)
        sub = random.choice(["www", "api", "cdn", "login", "fonts", ""])
        qname = f"{sub}.{domain}".lstrip(".")
        proc = random.choice(_BENIGN_PROCESSES)
        yield _make(
            "dns_query", _now(base_ts, random.randint(0, 59)),
            hostname=hostname, eid=22,
            dns_query=qname, dns_query_type="A",
            dns_response_code="NOERROR",
            dns_query_results=f"type: 1 1.2.3.{random.randint(1,254)};",
            dns_ttl=random.choice([300, 600, 3600]),
            process_name=proc, bytes_received=20,
        ), 0

    # 1–3 normal HTTPS connections
    for _ in range(random.randint(1, 3)):
        yield _make(
            "network", _now(base_ts, random.randint(0, 59)),
            hostname=hostname, eid=3,
            dest_ip=f"52.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
            dest_port=443,
            process_name=random.choice(_BENIGN_PROCESSES),
            user=random.choice(_BENIGN_USERS),
        ), 0

    # 1–2 process creations (browsing, office)
    for _ in range(random.randint(1, 2)):
        yield _make(
            "process", _now(base_ts, random.randint(0, 59)),
            hostname=hostname, eid=1,
            process_name=random.choice(_BENIGN_PROCESSES),
            parent_process=r"C:\Windows\explorer.exe",
            command_line="",
            user=random.choice(_BENIGN_USERS),
        ), 0


# ── Lateral movement attack scenario ────────────────────────────────────────

def generate_lateral_movement_attack(
    start_ts: datetime, target_host: str
) -> Iterator[tuple[NormalizedEvent, int]]:
    """One end-to-end PtH-style attack window (~3 minutes, ~20 events)."""
    attacker_ip = f"192.168.1.{random.randint(80, 99)}"
    victim_user = "compromised.user"

    # 1) Brute force: 4 failures, then 1 success
    for i in range(4):
        yield _make(
            "authentication", _now(start_ts, i * 2),
            hostname=target_host, eid=4625,
            source_ip=attacker_ip, user=victim_user, logon_type=3,
        ), 1

    yield _make(
        "authentication", _now(start_ts, 10),
        hostname=target_host, eid=4624,
        source_ip=attacker_ip, dest_ip="192.168.1.50",
        user=victim_user, logon_type=3,
    ), 1

    # 2) Special privileges granted
    yield _make(
        "authentication", _now(start_ts, 12),
        hostname=target_host, eid=4672,
        user=victim_user,
    ), 1

    # 3) NTLM auth (4776)
    yield _make(
        "authentication", _now(start_ts, 13),
        hostname=target_host, eid=4776,
        user=victim_user,
    ), 1

    # 4) Explicit credential (4648 — Pass-the-Hash)
    yield _make(
        "authentication", _now(start_ts, 15),
        hostname=target_host, eid=4648,
        source_ip=attacker_ip, user=victim_user,
    ), 1

    # 5) LSASS access (Sysmon EID 10) — mimikatz-like
    yield _make(
        "process_access", _now(start_ts, 18),
        hostname=target_host, eid=10,
        process_name=r"C:\Users\victim\AppData\Local\Temp\mimikatz.exe",
        user=victim_user,
    ), 1

    # 6) PowerShell with -EncodedCommand
    yield _make(
        "process", _now(start_ts, 22),
        hostname=target_host, eid=1,
        process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        parent_process=r"C:\Windows\System32\cmd.exe",
        command_line="powershell.exe -NoP -W Hidden -Enc " + _rand_subdomain(60, string.ascii_letters + string.digits + "+/="),
        user=victim_user,
    ), 1

    # 7) Lateral connections to multiple internal hosts on lateral ports
    for offset, port, internal_host in [
        (28, 445,  "192.168.1.51"),  # SMB
        (35, 3389, "192.168.1.52"),  # RDP
        (42, 5985, "192.168.1.53"),  # WinRM
        (48, 135,  "192.168.1.54"),  # WMI
    ]:
        yield _make(
            "network", _now(start_ts, offset),
            hostname=target_host, eid=3,
            source_ip="192.168.1.50", dest_ip=internal_host, dest_port=port,
            process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            user=victim_user,
        ), 1

    # 8) PsExec on victim
    yield _make(
        "process", _now(start_ts, 55),
        hostname=target_host, eid=1,
        process_name=r"C:\Tools\PsExec64.exe",
        parent_process=r"C:\Windows\System32\cmd.exe",
        command_line=r"PsExec64.exe \\192.168.1.51 -u admin -p Pass1 cmd.exe",
        user=victim_user,
    ), 1

    # 9) WMIC reconnaissance
    yield _make(
        "process", _now(start_ts, 60),
        hostname=target_host, eid=1,
        process_name=r"C:\Windows\System32\wbem\WMIC.exe",
        parent_process=r"C:\Windows\System32\cmd.exe",
        command_line=r"wmic /node:192.168.1.51 process call create cmd.exe",
        user=victim_user,
    ), 1


# ── DNS exfiltration attack scenario ────────────────────────────────────────

def generate_dns_exfiltration_attack(
    start_ts: datetime, source_host: str
) -> Iterator[tuple[NormalizedEvent, int]]:
    """One DNS tunneling burst (~1 minute, ~30 queries to one base domain)."""
    base_domain = random.choice([
        "tunnel.attacker.com", "exfil.evil.net", "c2.malicious.io"
    ])
    tool_path = r"C:\Users\victim\AppData\Local\Temp\dnstun.exe"

    for i in range(30):
        # Long random base32-ish subdomain (high entropy, looks encoded)
        sub = _rand_subdomain(random.randint(40, 60))
        # Mix record types — TXT mostly, some NULL, occasional A
        qtype = random.choices(
            ["TXT", "NULL", "A", "MX"],
            weights=[55, 20, 15, 10], k=1,
        )[0]
        # ~10% NXDOMAIN (probe channels in tunneling)
        rcode = "NXDOMAIN" if random.random() < 0.1 else "NOERROR"

        if rcode == "NXDOMAIN":
            results = "-"
            type_num = "16" if qtype == "TXT" else "1"
        else:
            type_num = {"A": "1", "TXT": "16", "NULL": "10", "MX": "15"}[qtype]
            payload = _rand_subdomain(random.randint(20, 80))
            results = f'type: {type_num} "{payload}";'

        yield _make(
            "dns_query", _now(start_ts, i * 2),
            hostname=source_host, eid=22,
            dns_query=f"{sub}.{base_domain}",
            dns_query_type=qtype,
            dns_response_code=rcode,
            dns_query_results=results,
            dns_ttl=random.choice([30, 60, 120]),  # low TTL = fast-flux signal
            process_name=tool_path,
            bytes_received=len(results),
        ), 1


# ── Top-level orchestrator ──────────────────────────────────────────────────

def generate_dataset(
    duration_hours: int = 24,
    hosts: Optional[list[str]] = None,
    lateral_attacks_per_day: int = 5,
    dns_attacks_per_day: int = 5,
    seed: Optional[int] = None,
) -> list[tuple[NormalizedEvent, int]]:
    """
    Generate a labeled synthetic dataset.

    Returns a list of (NormalizedEvent, label) sorted by timestamp.
    Each label is 1 if the event is part of an attack scenario, else 0.
    """
    if seed is not None:
        random.seed(seed)

    hosts = hosts or [f"LAPTOP-{i:03d}" for i in range(1, 6)]
    base = datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc)

    out: list[tuple[NormalizedEvent, int]] = []

    # 1) Normal background traffic per host per minute
    for host in hosts:
        for minute in range(duration_hours * 60):
            ts = base + timedelta(minutes=minute)
            out.extend(generate_normal_minute(ts, host))

    # 2) Lateral movement attacks scattered across days
    total_lat = lateral_attacks_per_day * max(1, duration_hours // 24)
    for _ in range(total_lat):
        target = random.choice(hosts)
        # Pick a random start time inside the duration window
        offset_min = random.randint(0, duration_hours * 60 - 5)
        out.extend(generate_lateral_movement_attack(
            base + timedelta(minutes=offset_min), target
        ))

    # 3) DNS exfiltration attacks scattered across days
    total_dns = dns_attacks_per_day * max(1, duration_hours // 24)
    for _ in range(total_dns):
        source = random.choice(hosts)
        offset_min = random.randint(0, duration_hours * 60 - 2)
        out.extend(generate_dns_exfiltration_attack(
            base + timedelta(minutes=offset_min), source
        ))

    out.sort(key=lambda x: x[0].timestamp)
    return out
