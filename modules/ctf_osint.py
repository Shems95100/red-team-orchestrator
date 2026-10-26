"""Offline OSINT triage for user-provided CTF artifacts."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urlparse

from core.context import Context, Finding
from core.scope import Scope
from modules.base import Module
from modules.ctf_patterns import build_flag_pattern

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]{1,300}", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class OsintTriage(Module):
    """Extracts indicators from local files; performs no DNS or web lookups."""

    name = "ctf-osint-triage"
    phase = "vuln"

    def __init__(self, artifact_paths: list[str] | None = None, flag_prefix: str | None = None):
        self.artifact_paths = [Path(path) for path in artifact_paths or []]
        self.flag_re = build_flag_pattern(flag_prefix)

    def should_run(self, ctx: Context) -> bool:
        return bool(self.artifact_paths)

    def run(self, ctx: Context, scope: Scope) -> None:
        for path in self.artifact_paths:
            try:
                data = path.read_bytes()
            except OSError as exc:
                ctx.log(self.name, f"Artefact illisible {path}: {exc}")
                continue
            if len(data) > MAX_ARTIFACT_BYTES:
                ctx.log(self.name, f"Artefact ignoré (limite 2 MiB dépassée): {path}")
                continue

            text = data.decode("utf-8", "replace")
            urls = list(dict.fromkeys(URL_RE.findall(text)))[:20]
            emails = list(dict.fromkeys(EMAIL_RE.findall(text)))[:20]
            domains = set(DOMAIN_RE.findall(text))
            domains.update(urlparse(url).hostname or "" for url in urls)
            domains.update(email.rsplit("@", 1)[-1] for email in emails)
            domains.discard("")
            ip_addresses = list(dict.fromkeys(IPV4_RE.findall(text)))[:20]
            flags = list(dict.fromkeys(self.flag_re.findall(text)))[:10]
            digest = hashlib.sha256(data).hexdigest()
            indicators = [*emails, *sorted(domains)[:20], *ip_addresses]
            evidence = (f"sha256={digest}; indicateurs={', '.join(indicators) if indicators else 'aucun'}; "
                        f"flags={', '.join(flags) if flags else 'aucun'}")
            ctx.add_finding(Finding(
                host="local-artifact",
                title=f"Flag CTF trouvé dans {path.name}" if flags else f"OSINT hors ligne : {path.name}",
                severity="medium" if flags else "info",
                confidence="firm",
                detail=(f"Artefact local de {len(data)} octets analysé sans requête réseau. "
                        f"URLs={len(urls)}, domaines={len(domains)}, adresses IPv4={len(ip_addresses)}, flags={len(flags)}."),
                evidence=evidence,
                source_module=self.name,
                remediation="Vérifier manuellement le contexte des indicateurs avant toute attribution.",
                steps=["Examiner l'artefact source local.", "Corréler les indicateurs uniquement dans le cadre du challenge autorisé."],
            ))
