"""Small bounded helpers for offline CTF artifact analysis."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


def read_artifact(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError(f"artefact supérieur à {MAX_ARTIFACT_BYTES // (1024 * 1024)} MiB")
    return data


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable_strings(data: bytes, limit: int = 50) -> list[str]:
    return [match.decode("ascii", "replace") for match in PRINTABLE_RE.findall(data)[:limit]]


def identify_format(data: bytes) -> str:
    if data.startswith(b"\x7fELF"):
        return "ELF executable/object"
    if data.startswith(b"MZ"):
        return "PE/DOS executable candidate"
    if data.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")):
        return "PCAP capture"
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        return "PCAPNG capture"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if data.startswith(b"%PDF-"):
        return "PDF document"
    if data.startswith(b"SQLite format 3\x00"):
        return "SQLite database"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP stream"
    if data.startswith((b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")):
        return "Mach-O executable"
    return "unknown/raw data"
