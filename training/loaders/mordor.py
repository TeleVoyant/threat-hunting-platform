# training/loaders/mordor.py
"""
Mordor / Security-Datasets loader.

Mordor (https://mordordatasets.com — now also distributed as the Open
Threat Research Forge "Security Datasets") is a community-curated set of
pre-recorded Windows attack telemetry, mostly Sysmon and Security event
logs. Each dataset is a JSONL file (one event per line) with FLAT
field names (Mordor format) — different from the nested Wazuh format
that our preprocessor consumes.

This loader translates Mordor events into the same `NormalizedEvent`
schema the runtime uses, so the SAME feature pipeline + detectors can
train on real attacker behaviour.

Labelling
---------
Mordor datasets are attack-only — they contain the events generated
DURING an attack scenario. We label every event in an attack dataset
as `1` (positive), and ASSUME the caller has separately supplied a
negative-class corpus (typically synthetic.generate_dataset() or the
benign-only Mordor "empire_*_baseline" datasets).

The dataset taxonomy maps to our two detectors as follows. Folder name
substring → which model treats it as positive:

  Lateral movement (LateralMovementDetector positives):
    lateral_movement_*, lm_*, credential_access_*, ca_*

  DNS exfiltration (DnsExfiltrationDetector positives):
    exfiltration_dns_*, ex_dns_*, exfil_dns_*, dnscat*, iodine*

  Everything else: negative (treated as benign baseline)

Layout
------
We accept either:
  - A single .json or .jsonl file (the caller specifies the label)
  - A directory containing .json/.jsonl files (label inferred from
    the file name OR the directory name — see _infer_label_from_path)

Mordor field translation
------------------------
Top-level event fields most commonly used:
  EventID                 → windows_event_id
  Hostname / Computer     → hostname
  @timestamp              → timestamp (ISO 8601)
  Channel                 → routes to Sysmon/Security/etc.

Sysmon-flavoured fields (Channel ∈ Microsoft-Windows-Sysmon/Operational):
  Image                   → process_name
  ParentImage             → parent_process
  CommandLine             → command_line
  User                    → user
  SourceIp                → source_ip
  DestinationIp           → dest_ip
  DestinationPort         → dest_port
  QueryName               → dns_query
  QueryStatus             → dns_response_code (mapped via DNS_STATUS)
  QueryResults            → dns_query_results

Security log fields (Channel == Security):
  TargetUserName          → user
  LogonType               → logon_type
  IpAddress               → source_ip   (semantic: who connected to us)

If a field is absent or unparseable, it is left as None — matching
NormalizedEvent's optional contract.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from shared.logging import get_logger
from shared.schemas import NormalizedEvent

logger = get_logger("training.loaders.mordor")


# ── Inferred labels from filename / dataset taxonomy ───────────────────────

_LABEL_PATTERNS_LATERAL_MOVEMENT = re.compile(
    r"(lateral_movement|^lm_|credential_access|^ca_|cred_dump|psexec|wmiexec|"
    r"smbexec|kerberoast|mimikatz|lsass|pass[_-]?the[_-]?(hash|ticket))",
    re.IGNORECASE,
)
_LABEL_PATTERNS_DNS_EXFIL = re.compile(
    r"(exfil(tration)?[_-]?dns|^ex[_-]?dns|dnscat|iodine|dns[_-]?(tunnel|exfil))",
    re.IGNORECASE,
)
_LABEL_PATTERNS_BENIGN = re.compile(
    r"(baseline|benign|normal|empire[_-]?\w+[_-]?baseline)",
    re.IGNORECASE,
)


def _infer_label_from_path(path: Path) -> Optional[str]:
    """
    Returns one of: 'lateral_movement', 'dns_exfiltration', 'benign', or None
    (caller must supply explicit label).
    """
    candidates = [path.stem, path.parent.name, path.parent.parent.name]
    blob = " ".join(candidates).lower()
    if _LABEL_PATTERNS_BENIGN.search(blob):
        return "benign"
    if _LABEL_PATTERNS_LATERAL_MOVEMENT.search(blob):
        return "lateral_movement"
    if _LABEL_PATTERNS_DNS_EXFIL.search(blob):
        return "dns_exfiltration"
    return None


# ── DNS status code → standard rcode (same mapping as preprocessor) ────────

_DNS_STATUS = {
    "0":    "NOERROR",
    0:      "NOERROR",
    "3":    "NXDOMAIN",
    3:      "NXDOMAIN",
    "9003": "NXDOMAIN",
    9003:   "NXDOMAIN",
    "9501": "NOERROR",
    9501:   "NOERROR",
    "2":    "SERVFAIL",
    2:      "SERVFAIL",
}

# DNS query type code → standard name
_DNS_QUERY_TYPE = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA",
    "10": "NULL", "15": "MX", "16": "TXT", "28": "AAAA",
    "33": "SRV", "255": "ANY",
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
    10: "NULL", 15: "MX", 16: "TXT", 28: "AAAA",
    33: "SRV", 255: "ANY",
}

# Known Sysmon and Security event channels in Mordor data
_SYSMON_CHANNEL    = "Microsoft-Windows-Sysmon"
_SECURITY_CHANNEL  = "Security"
_DNSCLIENT_CHANNEL = "Microsoft-Windows-DNS-Client"

_AUTH_EIDS    = {4624, 4625, 4648, 4672, 4768, 4769, 4776}
_ACCOUNT_EIDS = {4720, 4722, 4724, 4725, 4726, 4738}


# ── Loader ─────────────────────────────────────────────────────────────────

class MordorLoader:
    """
    Loads Mordor JSONL events and yields (NormalizedEvent, label) tuples.

    Statistics are tracked per load() so the caller can report dropped
    events, parse errors, and label distribution.
    """

    def __init__(self):
        self.stats = {
            "total":   0,
            "kept":    0,
            "dropped": 0,
            "parse_errors": 0,
            "by_label":     {},
            "by_event_id":  {},
        }

    # ── Public API ──────────────────────────────────────────────────────────

    def load_path(
        self,
        root: str,
        *,
        label_override: Optional[int] = None,
    ) -> list[tuple[NormalizedEvent, int]]:
        """
        Load a single file or every JSONL file in a directory tree.

        label_override: if provided (0 or 1), every event gets this label.
        Otherwise, label is inferred from the file path taxonomy:
          - path matches benign pattern  → label = 0
          - path matches lateral_movement or dns_exfiltration → label = 1
          - no match → SKIPPED with a warning (cannot label safely)
        """
        root_path = Path(root)
        if root_path.is_file():
            files = [root_path]
        elif root_path.is_dir():
            files = sorted(
                p for p in root_path.rglob("*")
                if p.is_file() and p.suffix.lower() in (".json", ".jsonl")
            )
        else:
            raise FileNotFoundError(f"Mordor path does not exist: {root}")

        out: list[tuple[NormalizedEvent, int]] = []
        for f in files:
            if label_override is not None:
                label = int(label_override)
                category = "override"
            else:
                inferred = _infer_label_from_path(f)
                if inferred is None:
                    logger.warning(
                        "Cannot infer label from filename, skipping",
                        file=str(f),
                    )
                    continue
                label = 0 if inferred == "benign" else 1
                category = inferred

            count_before = len(out)
            for event in self._iter_file(f):
                out.append((event, label))
            kept_here = len(out) - count_before
            self.stats["by_label"][category] = (
                self.stats["by_label"].get(category, 0) + kept_here
            )
            logger.info(
                "Loaded Mordor file",
                file=str(f), label=label, category=category, kept=kept_here,
            )

        return out

    # ── File-level iteration ────────────────────────────────────────────────

    def _iter_file(self, path: Path) -> Iterator[NormalizedEvent]:
        with open(path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, 1):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                self.stats["total"] += 1
                try:
                    obj = json.loads(raw_line)
                except json.JSONDecodeError:
                    self.stats["parse_errors"] += 1
                    continue
                event = self._translate(obj)
                if event is None:
                    self.stats["dropped"] += 1
                    continue
                self.stats["kept"] += 1
                self.stats["by_event_id"][event.windows_event_id] = (
                    self.stats["by_event_id"].get(event.windows_event_id, 0) + 1
                )
                yield event

    # ── Mordor flat JSON → NormalizedEvent ──────────────────────────────────

    def _translate(self, obj: dict) -> Optional[NormalizedEvent]:
        # EventID is the routing key
        eid = self._safe_int(obj.get("EventID") or obj.get("event_id"))
        if eid is None:
            return None

        channel = (obj.get("Channel") or obj.get("channel") or "").strip()
        ts = self._parse_timestamp(
            obj.get("@timestamp")
            or obj.get("EventTime")
            or obj.get("UtcTime")
        )
        if ts is None:
            return None

        hostname = (
            obj.get("Hostname") or obj.get("Computer")
            or obj.get("hostname") or "unknown"
        )

        base = {
            "event_id":         str(obj.get("RecordID") or obj.get("@timestamp") or
                                     f"{hostname}-{eid}-{ts.isoformat()}"),
            "timestamp":        ts,
            "source_ip":        "0.0.0.0",
            "hostname":         hostname,
            "windows_event_id": eid,
            "event_type":       "other",
            "raw":              obj,
        }

        # Route by channel + event ID
        if _SYSMON_CHANNEL in channel:
            self._extract_sysmon(eid, obj, base)
        elif _DNSCLIENT_CHANNEL in channel:
            self._extract_dns_client(obj, base)
        elif channel == _SECURITY_CHANNEL or eid in (_AUTH_EIDS | _ACCOUNT_EIDS):
            self._extract_security(eid, obj, base)
        else:
            # Unknown channel / unrouted EID — return as a generic event
            base["event_type"] = "other"

        try:
            return NormalizedEvent(**base)
        except Exception as e:
            logger.debug("Mordor event rejected by schema",
                         eid=eid, channel=channel, error=str(e))
            return None

    # ── Sysmon translation ─────────────────────────────────────────────────

    def _extract_sysmon(self, eid: int, obj: dict, out: dict) -> None:
        if eid == 1:        # Process Creation
            out["event_type"]   = "process"
            out["process_name"] = obj.get("Image")
            out["parent_process"] = obj.get("ParentImage")
            out["command_line"] = obj.get("CommandLine")
            out["user"]         = obj.get("User")
        elif eid == 3:      # Network Connection
            out["event_type"] = "network"
            out["source_ip"]  = obj.get("SourceIp", out["source_ip"])
            out["dest_ip"]    = obj.get("DestinationIp")
            out["dest_port"]  = self._safe_int(obj.get("DestinationPort"))
            out["process_name"] = obj.get("Image")
            out["user"]       = obj.get("User")
        elif eid == 7:
            out["event_type"]   = "image_load"
            out["process_name"] = obj.get("Image")
        elif eid == 8:
            out["event_type"]   = "remote_thread"
            out["process_name"] = obj.get("SourceImage")
        elif eid == 10:     # LSASS access etc.
            out["event_type"]   = "process_access"
            out["process_name"] = obj.get("SourceImage")
        elif eid == 11:
            out["event_type"]   = "file_create"
            out["process_name"] = obj.get("Image")
        elif eid in (12, 13, 14):
            out["event_type"]   = "registry"
            out["process_name"] = obj.get("Image")
        elif eid in (17, 18):
            out["event_type"]   = "pipe"
            out["process_name"] = obj.get("Image")
        elif eid in (19, 20, 21):
            out["event_type"]   = "wmi"
        elif eid == 22:     # DNS Query
            out["event_type"]   = "dns_query"
            out["dns_query"]    = obj.get("QueryName")
            out["process_name"] = obj.get("Image")
            status = str(obj.get("QueryStatus", "0"))
            out["dns_response_code"] = _DNS_STATUS.get(status, f"UNKNOWN_{status}")
            results = obj.get("QueryResults")
            if results and results != "-":
                out["dns_query_results"] = results
                m = re.search(r"type:\s*(\d+)", str(results))
                if m:
                    out["dns_query_type"] = _DNS_QUERY_TYPE.get(m.group(1))
                out["bytes_received"] = len(str(results).encode())
        elif eid == 25:
            out["event_type"]   = "process_tamper"
            out["process_name"] = obj.get("Image")

    # ── DNS-Client translation ─────────────────────────────────────────────

    def _extract_dns_client(self, obj: dict, out: dict) -> None:
        out["event_type"] = "dns_query"
        out["dns_query"]  = obj.get("QueryName")
        type_raw = str(obj.get("QueryType", "")).strip()
        if type_raw:
            out["dns_query_type"] = _DNS_QUERY_TYPE.get(type_raw, type_raw)
        status_raw = str(obj.get("QueryStatus", "0")).strip()
        out["dns_response_code"] = _DNS_STATUS.get(status_raw, f"UNKNOWN_{status_raw}")
        ttl = self._safe_int(obj.get("ttl") or obj.get("TTL"))
        if ttl is not None:
            out["dns_ttl"] = ttl

    # ── Security log translation ───────────────────────────────────────────

    def _extract_security(self, eid: int, obj: dict, out: dict) -> None:
        if eid in _AUTH_EIDS:
            out["event_type"] = "authentication"
            out["user"] = (
                obj.get("TargetUserName") or obj.get("SubjectUserName")
            )
            lt = self._safe_int(obj.get("LogonType"))
            if lt is not None:
                out["logon_type"] = lt
            ip = obj.get("IpAddress") or obj.get("WorkstationName")
            if ip and ip not in ("-", "::1", "127.0.0.1", "::"):
                # ipAddress = where auth came FROM (attacker on lateral move)
                out["source_ip"] = ip
                # dest_ip stays unset — Mordor data is per-victim-host
        elif eid in _ACCOUNT_EIDS:
            out["event_type"] = "account_management"
            out["user"] = (
                obj.get("TargetUserName") or obj.get("SubjectUserName")
            )
        else:
            out["event_type"] = "security"
            out["user"] = obj.get("SubjectUserName")

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_timestamp(value) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if not isinstance(value, str):
            return None
        s = value.rstrip("Z")
        # Strip nanosecond precision if present (Mordor sometimes has 9 digits)
        if "." in s:
            head, dot, tail = s.partition(".")
            if dot:
                tail = tail[:6]   # truncate to microseconds
                s = f"{head}.{tail}"
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None
