#!/usr/bin/env python3
"""
Normalise PowerShell script files so PS 5.1 on Windows parses them
identically regardless of the editor / OS that produced the source bytes.

Idempotent — safe to run repeatedly. Re-running on an already-normalised
file is a no-op (no rewrite, no mtime change).

Rules applied:
  1. Strip any existing UTF-8 BOM, then re-prepend one. PS 5.1 without a
     BOM defaults to Windows-1252 codepage interpretation, mangling
     non-ASCII characters in comments.
  2. Convert all line endings to CRLF. PS 5.1's tokeniser intermittently
     mis-nests braces in scripts with LF-only endings, especially in nested
     try/catch + if-as-expression constructs. CRLF avoids the class of bug.
  3. Strip trailing whitespace from each line (cosmetic; reduces diff
     noise when editors disagree on auto-trim behaviour).

This is run automatically by:
  - `make normalize-handler` (single file, scripts/agent_command_handler.ps1)
  - `make normalize-ps1` (every .ps1 under scripts/)

It is also the same normalisation the server-side HandlerVersionStore
applies to bytes uploaded via /admin/handler/upload + /admin/handler/scan,
so the on-disk source and the OTA-served bytes always match what an
endpoint receives.

Usage:
  python3 scripts/normalize_ps1.py path/to/file.ps1 [more.ps1 ...]
  python3 scripts/normalize_ps1.py --all   # walks scripts/*.ps1

Exit code 0 even on no-op; non-zero only on read/write errors.
"""

from __future__ import annotations

import sys
from pathlib import Path


_BOM = b"\xef\xbb\xbf"


def normalise_bytes(data: bytes) -> bytes:
    """Return the canonical CRLF + UTF-8-BOM form of `data`.

    Strips an existing BOM (if any), normalises line endings via the
    two-step LF→CRLF dance (handles mixed input cleanly), strips trailing
    whitespace per line, and re-prepends a single BOM.
    """
    if data.startswith(_BOM):
        data = data[len(_BOM):]
    # First collapse any CRLF → LF so the next replace doesn't double-up
    # (LF → CRLF applied to a CRLF would yield CRCRLF).
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    # Strip trailing whitespace per line for diff cleanliness.
    lines = [ln.rstrip() for ln in data.split(b"\n")]
    data = b"\r\n".join(lines)
    return _BOM + data


def normalise_file(path: Path) -> str:
    """Apply normalisation to `path`. Returns a status word:
      "ok"      — file was already canonical, nothing written
      "fixed"   — file rewritten with canonical form
      "missing" — file does not exist
    """
    if not path.exists():
        return "missing"
    original = path.read_bytes()
    canonical = normalise_bytes(original)
    if original == canonical:
        return "ok"
    path.write_bytes(canonical)
    return "fixed"


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    paths: list[Path]
    if argv[0] == "--all":
        paths = sorted(Path("scripts").glob("*.ps1"))
        if not paths:
            print("no .ps1 files under scripts/", file=sys.stderr)
            return 0
    else:
        paths = [Path(a) for a in argv]

    rc = 0
    for p in paths:
        try:
            status = normalise_file(p)
        except OSError as e:
            print(f"  ERROR  {p}: {e}", file=sys.stderr)
            rc = 1
            continue
        marker = {"ok": " ok    ", "fixed": " fixed ", "missing": "MISSING"}[status]
        print(f"  {marker} {p}")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
