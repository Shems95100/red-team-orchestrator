"""Shared flag-pattern construction for CTF-only discovery modules."""

from __future__ import annotations

import re

DEFAULT_FLAG_PATTERN = r"(?<![A-Za-z0-9_])[A-Za-z0-9_]{2,16}\{[^}\r\n]{1,160}\}"


def build_flag_pattern(prefix: str | None = None) -> re.Pattern[str]:
    if prefix is None or not prefix.strip():
        return re.compile(DEFAULT_FLAG_PATTERN)

    normalized = prefix.strip()
    if normalized.endswith("{"):
        normalized = normalized[:-1]
    if not normalized or len(normalized) > 32:
        raise ValueError("Le préfixe de flag doit contenir entre 1 et 32 caractères.")
    return re.compile(re.escape(normalized) + r"\{[^}\r\n]{1,160}\}", re.IGNORECASE)
