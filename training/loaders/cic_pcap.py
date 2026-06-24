#!/usr/bin/env python3
# training/loaders/cic_pcap.py
"""
CIC-Bell-DNS-Exf PCAP -> NormalizedEvent JSONL loader (HOST-SIDE prep tool).

Converts the CIRA-CIC-BELL-DNS-EXF-2021 packet captures into labelled
NormalizedEvent JSONL that the existing --from-jsonl path consumes
(training/train_models.py::load_jsonl, training/evaluate_models.py::load_dataset).

IMPORTANT - runs on a workstation, NOT inside the API container.
It requires the `tshark` system binary. The container only ever consumes the
resulting JSONL (pure stdlib), so tshark is deliberately NOT a container/pip
dependency and nothing is added to requirements.lock.txt.

Labelling (validated empirically against the dataset)
-----------------------------------------------------
The capture snaplen is 96 bytes, so the large DNS-exfiltration queries are
truncated (frame.cap_len < frame.len) while their intended UDP length stays
large (>= 270). The surviving ~42-byte QNAME prefix still carries the
high-entropy encoded payload (e.g. "0.J4HgHlgzQH6j0YOV8m1hdnpvv...").

  - Attack PCAPs  -> only the truncated large DNS queries become positives
                    (label 1); the QNAME is reconstructed from the raw payload.
  - Benign PCAPs  -> readable queries (dns.qry.name) become negatives
                    (label 0), excluding mDNS/.local and reverse-DNS .arpa noise.

Each PCAP contributes a single class (attack->positives, benign->negatives) so
windowed labels never mix. Heuristic precision measured: 99.2-99.8% in attack
PCAPs vs 0.09-0.11% leakage in benign PCAPs.

Usage
-----
    python -m training.loaders.cic_pcap \
        --pcap-dir data/datasets/CIC-Bell-DNS-Exf/PCAP \
        --output   data/datasets/cic_bell_dns.jsonl \
        [--max-per-file 20000]
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

# Make `python -m training.loaders.cic_pcap` work from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from shared.logging import get_logger, setup_logging
from shared.schemas import NormalizedEvent

logger = get_logger("training.loaders.cic_pcap")


# DNS numeric query-type -> standard name (same mapping the preprocessor uses)
_DNS_TYPE = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "10": "NULL",
    "15": "MX", "16": "TXT", "28": "AAAA", "33": "SRV", "255": "ANY",
}
_MAX_DNS_QUERY_LENGTH = 253  # matches EventPreprocessor.MAX_DNS_QUERY_LENGTH

# tshark -T fields output order (default separator is TAB)
_TSHARK_FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst", "udp.dstport",
    "udp.length", "dns.qry.name", "dns.qry.type", "udp.payload",
]

# Exfil channel: response queries truncated by the 96-byte snaplen with a
# large intended UDP length.
_ATTACK_FILTER = "dns.flags.response==0 && frame.cap_len<frame.len && udp.length>=270"
# Benign: any readable query name (noise filtered in Python).
_BENIGN_FILTER = "dns.flags.response==0 && dns.qry.name"


# ---------------------------------------------------------------------------
# QNAME reconstruction from raw (truncated) DNS-over-UDP payload
# ---------------------------------------------------------------------------

def qname_from_payload(hexstr: str) -> str:
    """
    Decode the QNAME from a (possibly truncated) DNS payload hex string.

    The DNS header is 12 bytes; the QNAME is a sequence of length-prefixed
    labels. The dataset's 96-byte snaplen cuts the QNAME mid-label, so we KEEP
    the surviving partial final label (this is where the encoded exfil payload
    lives) rather than dropping it.
    """
    try:
        b = bytes.fromhex(hexstr.replace(":", ""))
    except ValueError:
        return ""
    i = 12
    labels: list[str] = []
    while i < len(b):
        ln = b[i]
        if ln == 0 or ln > 63:
            break
        if i + 1 + ln > len(b):
            # truncated final label -- keep the surviving bytes
            tail = b[i + 1:].decode("latin1", "replace")
            if tail:
                labels.append(tail)
            break
        labels.append(b[i + 1:i + 1 + ln].decode("latin1", "replace"))
        i += 1 + ln
    return ".".join(lbl for lbl in labels if lbl)


# ---------------------------------------------------------------------------
# tshark extraction
# ---------------------------------------------------------------------------

def _run_tshark(pcap: Path, display_filter: str) -> Iterator[list[str]]:
    cmd = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for f in _TSHARK_FIELDS:
        cmd += ["-e", f]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "tshark not found. Install Wireshark/tshark and run this loader on "
            "the host (it is a host-side dataset-prep tool, not a container dep)."
        ) from exc
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line.rstrip("\n").split("\t")
    proc.wait()


def _parse_ts(epoch: str) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    except (ValueError, OSError):
        return None


def iter_pcap(
    pcap: Path, is_attack: bool, max_events: Optional[int] = None
) -> Iterator[tuple[NormalizedEvent, int]]:
    """Yield (NormalizedEvent, label) tuples for one PCAP."""
    flt = _ATTACK_FILTER if is_attack else _BENIGN_FILTER
    hostname = "CIC-EXFIL" if is_attack else "CIC-BENIGN"
    label = 1 if is_attack else 0

    n = 0
    for row in _run_tshark(pcap, flt):
        row += [""] * (len(_TSHARK_FIELDS) - len(row))
        ts_s, src, dst, dport, _ulen, qname, qtype, payload = row[:8]

        ts = _parse_ts(ts_s)
        if ts is None:
            continue

        if is_attack:
            q = qname_from_payload(payload)
        else:
            q = (qname or "").split(",")[0].strip().lower()
            if not q or ".arpa" in q or ".local" in q:
                continue
        if not q:
            continue
        q = q[:_MAX_DNS_QUERY_LENGTH]

        qt = None
        if qtype:
            qt = _DNS_TYPE.get(qtype.split(",")[0].strip())

        try:
            port = int(dport) if dport else 53
        except ValueError:
            port = 53

        try:
            ev = NormalizedEvent(
                event_id=f"{ts_s}-{src or '0'}-{q[:8]}-{n}",
                timestamp=ts,
                source_ip=src or "0.0.0.0",
                dest_ip=dst or None,
                dest_port=port,
                hostname=hostname,
                event_type="dns_query",
                dns_query=q,
                dns_query_type=qt,
                bytes_received=0,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Event rejected by schema", error=str(exc))
            continue

        yield ev, label
        n += 1
        if max_events and n >= max_events:
            break


def load_dir(
    pcap_dir: Path, max_per_file: Optional[int] = None
) -> Iterator[tuple[NormalizedEvent, int]]:
    """Walk PCAP/Attacks and PCAP/Benign, yielding labelled events."""
    attacks = sorted((pcap_dir / "Attacks").glob("*.pcap"))
    benign = sorted((pcap_dir / "Benign").glob("*.pcap"))
    if not attacks and not benign:
        raise FileNotFoundError(
            f"No PCAPs under {pcap_dir}/Attacks or {pcap_dir}/Benign"
        )
    for p in attacks:
        logger.info("Processing attack PCAP", file=p.name)
        yield from iter_pcap(p, True, max_per_file)
    for p in benign:
        logger.info("Processing benign PCAP", file=p.name)
        yield from iter_pcap(p, False, max_per_file)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Convert CIC-Bell-DNS-Exf PCAPs to labelled NormalizedEvent JSONL"
    )
    ap.add_argument("--pcap-dir", required=True,
                    help="Path to CIC-Bell-DNS-Exf/PCAP (with Attacks/ and Benign/)")
    ap.add_argument("--output", required=True,
                    help="Output JSONL path (one NormalizedEvent + _label per line)")
    ap.add_argument("--max-per-file", type=int, default=0,
                    help="Cap events per PCAP (0 = no cap). Useful for fast/balanced runs.")
    args = ap.parse_args()

    setup_logging("INFO")

    pcap_dir = Path(args.pcap_dir)
    if not pcap_dir.is_dir():
        logger.error("PCAP dir not found", path=str(pcap_dir))
        return 1

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    max_pf = args.max_per_file or None

    pos = neg = 0
    with open(out, "w") as f:
        for ev, lbl in load_dir(pcap_dir, max_pf):
            obj = ev.model_dump(mode="json")
            obj["_label"] = lbl
            f.write(json.dumps(obj) + "\n")
            if lbl == 1:
                pos += 1
            else:
                neg += 1

    logger.info("CIC PCAP load complete", positives=pos, negatives=neg,
                total=pos + neg, output=str(out))
    print(f"\nWrote {pos + neg} events ({pos} exfil / {neg} benign) to {out}")
    if pos == 0 or neg == 0:
        print("WARNING: one class is empty -- check the PCAP directory layout.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
