# ingestion/preprocessor.py
"""
Event preprocessor: extracts from Wazuh's nested alert format, validates,
sanitises, then produces NormalizedEvent objects.

Two-phase design:
  Phase 1 — Extraction: nested Wazuh JSON  →  flat field dict
  Phase 2 — Validation: field-level checks →  NormalizedEvent (Pydantic)

Without Phase 1, NormalizedEvent(**raw) rejects every real Wazuh event
because the fields live inside data.win.eventdata.* not at the top level.
"""

import re
import uuid
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Optional

from pydantic import ValidationError

from shared.schemas import NormalizedEvent
from shared.logging import get_logger
from ingestion.dead_letter import DeadLetterQueue

logger = get_logger("ingestion.preprocessor")

# ── Wazuh event provider identifiers ─────────────────────────────────────────
_SYSMON_PROVIDER      = "Microsoft-Windows-Sysmon"
_DNS_CLIENT_PROVIDER  = "Microsoft-Windows-DNS-Client"
_SECURITY_PROVIDER    = "Microsoft-Windows-Security-Auditing"
_WMI_PROVIDER         = "Microsoft-Windows-WMI-Activity"
_DEFENDER_PROVIDER    = "Microsoft-Windows-Windows Defender"
_TASKS_PROVIDER       = "Microsoft-Windows-TaskScheduler"

# Windows Security authentication event IDs
_AUTH_EIDS      = {4624, 4625, 4648, 4672, 4768, 4769, 4776}
_ACCOUNT_EIDS   = {4720, 4722, 4724, 4725, 4726, 4738}
_SERVICE_EIDS   = {7045, 7040}
_TASK_EIDS      = {106, 140, 141}

# DNS query type: Windows numeric code → standard name
# Used by both Sysmon EID 22 (parsed from QueryResults) and DNS Client EID 3008
_DNS_QUERY_TYPE: dict[str, str] = {
    "1":   "A",
    "2":   "NS",
    "5":   "CNAME",
    "6":   "SOA",
    "10":  "NULL",
    "15":  "MX",
    "16":  "TXT",
    "28":  "AAAA",
    "33":  "SRV",
    "255": "ANY",
}

# DNS status: Windows error code → RFC rcode name
# Sysmon queryStatus uses Windows DNS error codes; DNS Client EID 3008 uses RFC codes.
_DNS_STATUS: dict[str, str] = {
    "0":    "NOERROR",
    "1":    "FORMERR",
    "2":    "SERVFAIL",
    "3":    "NXDOMAIN",
    "4":    "NOTIMP",
    "5":    "REFUSED",
    "9003": "NXDOMAIN",  # Windows DNS_ERROR_RCODE_NAME_ERROR
    "9501": "NOERROR",   # Windows DNS_INFO_NO_RECORDS (empty NOERROR)
    "9002": "SERVFAIL",  # Windows DNS_ERROR_RCODE_SERVER_FAILURE
    "9004": "NOTIMP",
    "9005": "REFUSED",
}

# Regex to extract query type from Sysmon EID 22 QueryResults field.
# Format: "type: 16 \"some data\";" or "type: 1 1.2.3.4;"
_SYSMON_TYPE_RE = re.compile(r"type:\s*(\d+)", re.IGNORECASE)

# Injection / null-byte patterns
_INJECTION_RE = re.compile(
    r"(\x00|<script|javascript:|data:text/html|%00|%0a|%0d|\r\n|\n\r)",
    re.IGNORECASE,
)


class EventPreprocessor:

    MAX_COMMAND_LINE_LENGTH = 8192   # 8 KB
    MAX_DNS_QUERY_LENGTH    = 253    # DNS RFC limit
    MAX_PROCESS_NAME_LENGTH = 260    # Windows MAX_PATH
    MAX_EVENT_AGE_HOURS     = 24
    MAX_FUTURE_DRIFT_SECS   = 300    # 5 minutes
    MAX_PORT                = 65535
    MAX_TTL                 = 604800 # 7 days in seconds

    def __init__(self, dead_letter: Optional[DeadLetterQueue] = None):
        self.dead_letter = dead_letter or DeadLetterQueue()
        self._stats = {"processed": 0, "rejected": 0, "sanitized": 0}
        # Instance copy so /diag/preprocessor/backfill can widen this without
        # changing the class default for other callers.
        self.max_event_age_hours = self.MAX_EVENT_AGE_HOURS

    def set_backfill_window(self, hours: int) -> None:
        """Temporarily widen the max-age cutoff (hh). Used after an outage so
        a batch of older Wazuh archives can be re-ingested without being
        dead-lettered. Call again with the default to restore normal behaviour."""
        if hours < 1 or hours > 24 * 30:
            raise ValueError("backfill window must be 1h .. 30d")
        self.max_event_age_hours = hours
        logger.warning("Preprocessor backfill window set", hours=hours)

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────

    def normalize_batch(self, raw_events: list[dict]) -> list[NormalizedEvent]:
        results = []
        for raw in raw_events:
            try:
                event = self._validate_and_normalize(raw)
                if event:
                    results.append(event)
                    self._stats["processed"] += 1
            except Exception as e:
                self._stats["rejected"] += 1
                logger.warning(
                    "Event rejected",
                    reason=str(e),
                    event_id=raw.get("id", "unknown"),
                )
                self.dead_letter.enqueue(raw, reason=str(e))
        return results

    def get_stats(self) -> dict:
        return dict(self._stats)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 1 — EXTRACTION  (Wazuh nested format → flat dict)
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_wazuh_event(self, raw: dict) -> dict:
        """
        Wazuh alert objects nest Windows event fields inside
        data.win.system and data.win.eventdata. This method flattens
        them into the shape NormalizedEvent expects.
        """
        win      = raw.get("data", {}).get("win", {})
        sys_data = win.get("system", {})
        evt      = win.get("eventdata", {})
        agent    = raw.get("agent", {})

        eid      = self._safe_int(sys_data.get("eventID", "0"))
        provider = sys_data.get("providerName", "")

        out: dict = {
            "event_id":         raw.get("id") or sys_data.get("eventRecordID") or str(uuid.uuid4()),
            "timestamp":        raw.get("timestamp") or sys_data.get("systemTime"),
            "hostname":         agent.get("name") or sys_data.get("computer", "unknown"),
            "source_ip":        agent.get("ip", "0.0.0.0"),
            "windows_event_id": eid,
            "event_type":       "other",
            "raw":              raw,
        }

        if _SYSMON_PROVIDER in provider:
            self._extract_sysmon(eid, evt, out)
        elif _DNS_CLIENT_PROVIDER in provider:
            self._extract_dns_client(eid, evt, out)
        elif _SECURITY_PROVIDER in provider or eid in (_AUTH_EIDS | _ACCOUNT_EIDS):
            self._extract_security(eid, evt, out)
        elif _WMI_PROVIDER in provider:
            out["event_type"] = "wmi"
        elif _DEFENDER_PROVIDER in provider:
            out["event_type"] = "defender"
        elif _TASKS_PROVIDER in provider or eid in _TASK_EIDS:
            out["event_type"] = "scheduled_task"
        elif eid in _SERVICE_EIDS:
            out["event_type"] = "service"
            out["process_name"] = evt.get("imagePath") or evt.get("serviceName")

        return out

    def _extract_sysmon(self, eid: int, evt: dict, out: dict) -> None:
        if eid == 1:   # Process Creation
            out["event_type"]   = "process"
            out["process_name"] = evt.get("image")
            out["parent_process"] = evt.get("parentImage")
            out["command_line"] = evt.get("commandLine")
            out["user"]         = evt.get("user")

        elif eid == 3:  # Network Connection
            out["event_type"] = "network"
            out["source_ip"]  = evt.get("sourceIp", out["source_ip"])
            out["dest_ip"]    = evt.get("destinationIp")
            out["dest_port"]  = self._safe_int(evt.get("destinationPort"))
            out["process_name"] = evt.get("image")
            out["user"]       = evt.get("user")

        elif eid == 7:  # Image Loaded
            out["event_type"]   = "image_load"
            out["process_name"] = evt.get("image")

        elif eid == 8:  # CreateRemoteThread
            out["event_type"]   = "remote_thread"
            out["process_name"] = evt.get("sourceImage")

        elif eid == 10:  # Process Access (LSASS dump)
            out["event_type"]   = "process_access"
            out["process_name"] = evt.get("sourceImage")

        elif eid == 11:  # File Create
            out["event_type"]   = "file_create"
            out["process_name"] = evt.get("image")

        elif eid in (12, 13, 14):  # Registry events
            out["event_type"]   = "registry"
            out["process_name"] = evt.get("image")

        elif eid in (17, 18):  # Pipe events
            out["event_type"]   = "pipe"
            out["process_name"] = evt.get("image")

        elif eid in (19, 20, 21):  # WMI subscription
            out["event_type"]   = "wmi"

        elif eid == 22:  # DNS Query — primary source for dns_exfiltration detector
            out["event_type"] = "dns_query"
            out["dns_query"]  = evt.get("queryName")
            out["process_name"] = evt.get("image")

            status_raw = str(evt.get("queryStatus", "0"))
            out["dns_response_code"] = _DNS_STATUS.get(status_raw, f"UNKNOWN_{status_raw}")

            results = evt.get("queryResults", "")
            if results and results != "-":
                out["dns_query_results"] = results
                # Infer query type from QueryResults "type: <n>" prefix
                m = _SYSMON_TYPE_RE.search(results)
                if m:
                    out["dns_query_type"] = _DNS_QUERY_TYPE.get(m.group(1))
                # Estimate response size from results string length when bytes_received = 0
                out["bytes_received"] = len(results.encode())

        elif eid == 25:  # Process Tampering
            out["event_type"]   = "process_tamper"
            out["process_name"] = evt.get("image")

    def _extract_dns_client(self, eid: int, evt: dict, out: dict) -> None:
        """
        Microsoft-Windows-DNS-Client/Operational events.
        EID 3006: query initiated, EID 3008: response received, EID 3020: completed.
        These supply dns_query_type (A/TXT/NULL/etc.) and dns_ttl that Sysmon EID 22 lacks.
        """
        out["event_type"] = "dns_query"
        out["dns_query"]  = evt.get("queryName")

        type_raw = str(evt.get("queryType", "")).strip()
        if type_raw:
            out["dns_query_type"] = _DNS_QUERY_TYPE.get(type_raw, type_raw)

        status_raw = str(evt.get("queryStatus", "0")).strip()
        out["dns_response_code"] = _DNS_STATUS.get(status_raw, f"UNKNOWN_{status_raw}")

        ttl_raw = evt.get("ttl")
        if ttl_raw is not None:
            out["dns_ttl"] = self._safe_int(ttl_raw)

        # Destination (the DNS server queried)
        server = evt.get("serverList") or evt.get("dnsServerIpAddress")
        if server:
            out["dest_ip"]   = server.split(";")[0].strip() or None
            out["dest_port"] = 53  # DNS Client always uses port 53

    def _extract_security(self, eid: int, evt: dict, out: dict) -> None:
        if eid in _AUTH_EIDS:
            out["event_type"] = "authentication"
            out["user"]       = evt.get("targetUserName") or evt.get("subjectUserName")
            logon_type = evt.get("logonType")
            if logon_type:
                out["logon_type"] = self._safe_int(logon_type)

            # Semantics for auth events:
            #   ipAddress = where the auth REQUEST came from (the attacker on lateral mvmt)
            #   agent.ip  = the host BEING authenticated to (the target)
            # We map source_ip = attacker, dest_ip = target (this agent).
            src_ip   = evt.get("ipAddress")
            agent_ip = out["source_ip"]   # was set to agent.ip earlier
            if src_ip and src_ip not in ("-", "::1", "127.0.0.1", "::"):
                out["source_ip"] = src_ip
                out["dest_ip"]   = agent_ip
            # Note: ipPort is the source port for inbound auth — not stored.
        elif eid in _ACCOUNT_EIDS:
            out["event_type"] = "account_management"
            out["user"]       = evt.get("targetUserName") or evt.get("subjectUserName")
        else:
            out["event_type"] = "security"
            out["user"]       = evt.get("subjectUserName")

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 2 — VALIDATION  (field-level checks)
    # ─────────────────────────────────────────────────────────────────────────

    def _validate_and_normalize(self, raw: dict) -> Optional[NormalizedEvent]:
        # Extract from Wazuh nested format first
        flat = self._extract_wazuh_event(raw)

        # FR-01: pseudonymize PII fields (usernames, user-path embeddings)
        # before they enter the NormalizedEvent + downstream stores.
        # Toggleable via APT_ANONYMIZE env var (default on).
        from shared.anonymizer import anonymize_event
        flat = anonymize_event(flat)

        # ── Timestamp ────────────────────────────────────────────────────────
        ts = flat.get("timestamp")
        if ts:
            parsed_ts = self._parse_timestamp(ts)
            if not parsed_ts:
                raise ValueError(f"Unparseable timestamp: {ts!r}")
            now = datetime.now(timezone.utc)
            if parsed_ts.tzinfo is None:
                parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
            if parsed_ts < now - timedelta(hours=self.max_event_age_hours):
                raise ValueError(f"Event too old: {parsed_ts}")
            if parsed_ts > now + timedelta(seconds=self.MAX_FUTURE_DRIFT_SECS):
                raise ValueError(f"Event timestamp in future: {parsed_ts}")
            flat["timestamp"] = parsed_ts

        # ── IP addresses ─────────────────────────────────────────────────────
        for field in ("source_ip", "dest_ip"):
            val = flat.get(field)
            if val and val not in ("0.0.0.0", "-", "::"):
                try:
                    ipaddress.ip_address(val)
                except ValueError:
                    if field == "dest_ip":
                        flat[field] = None  # dest_ip is optional — drop bad value
                    else:
                        raise ValueError(f"Invalid IP in {field}: {val!r}")

        # ── Port ─────────────────────────────────────────────────────────────
        port = flat.get("dest_port")
        if port is not None and not (0 <= port <= self.MAX_PORT):
            flat["dest_port"] = None

        # ── DNS query length (RFC 2181 limit) ────────────────────────────────
        dns_query = flat.get("dns_query")
        if dns_query and len(dns_query) > self.MAX_DNS_QUERY_LENGTH:
            raise ValueError(f"DNS query exceeds RFC limit ({len(dns_query)} chars)")

        # ── DNS TTL range ────────────────────────────────────────────────────
        ttl = flat.get("dns_ttl")
        if ttl is not None and not (0 <= ttl <= self.MAX_TTL):
            flat["dns_ttl"] = None

        # ── String length limits ─────────────────────────────────────────────
        cmd = flat.get("command_line")
        if cmd and len(cmd) > self.MAX_COMMAND_LINE_LENGTH:
            flat["command_line"] = cmd[: self.MAX_COMMAND_LINE_LENGTH]
            self._stats["sanitized"] += 1

        proc = flat.get("process_name")
        if proc and len(proc) > self.MAX_PROCESS_NAME_LENGTH:
            raise ValueError(f"Process name too long: {len(proc)} chars")

        # ── Injection pattern check ──────────────────────────────────────────
        for field in ("user", "hostname", "process_name", "dns_query"):
            val = flat.get(field)
            if val and _INJECTION_RE.search(str(val)):
                raise ValueError(f"Injection pattern in field '{field}'")

        # ── Byte counters sanity ─────────────────────────────────────────────
        for field in ("bytes_sent", "bytes_received"):
            val = flat.get(field, 0)
            if not isinstance(val, (int, float)) or val < 0 or val > 10_000_000_000:
                flat[field] = 0

        # ── Pydantic final validation ────────────────────────────────────────
        try:
            return NormalizedEvent(**flat)
        except ValidationError as e:
            raise ValueError(f"Schema validation failed: {e.error_count()} errors — {e.errors()[0]}")

    # ─────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_timestamp(self, ts) -> Optional[datetime]:
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, str):
            # ISO8601 first — handles "+00:00" offsets, fractional seconds,
            # and the lone "Z" Wazuh sometimes emits (ii).
            s = ts.strip()
            iso = s[:-1] + "+00:00" if s.endswith("Z") else s
            try:
                return datetime.fromisoformat(iso)
            except ValueError:
                pass
            # Legacy strptime fallbacks (older Wazuh decoders, custom rules).
            stripped = s.rstrip("Z")
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    return datetime.strptime(stripped, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return None

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
