"""Offline metadata and flag triage for forensic CTF artifacts."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from core.context import Context, Finding
from core.scope import Scope
from modules.artifact_analysis import identify_format, printable_strings, read_artifact, sha256
from modules.base import Module
from modules.ctf_patterns import build_flag_pattern


class ForensicsTriage(Module):
    name = "ctf-forensics-triage"
    phase = "vuln"

    def __init__(self, artifact_paths: list[str] | None = None, flag_prefix: str | None = None):
        self.artifact_paths = [Path(path) for path in artifact_paths or []]
        self.flag_re = build_flag_pattern(flag_prefix)

    def should_run(self, ctx: Context) -> bool:
        return bool(self.artifact_paths)

    def _archive_members(self, data: bytes) -> list[str]:
        if not data.startswith(b"PK\x03\x04"):
            return []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                return archive.namelist()[:50]
        except (OSError, zipfile.BadZipFile, RuntimeError):
            return []

    def run(self, ctx: Context, scope: Scope) -> None:
        for path in self.artifact_paths:
            try:
                data = read_artifact(path)
            except (OSError, ValueError) as exc:
                ctx.log(self.name, f"Artefact ignoré {path}: {exc}")
                continue

            flags = list(dict.fromkeys(self.flag_re.findall(data.decode("latin-1"))))[:10]
            strings = printable_strings(data)
            members = self._archive_members(data)
            interesting = [value for value in strings if any(
                marker in value.lower() for marker in ("flag", "ctf", "user", "password", "timestamp", "author")
            )][:15]
            archive_detail = f"; membres ZIP={len(members)}" if members else ""
            ctx.add_finding(Finding(
                host="local-artifact",
                title=f"Flag forensique trouvé dans {path.name}" if flags else f"Triage forensique : {path.name}",
                severity="medium" if flags else "info",
                confidence="firm",
                detail=(f"Format={identify_format(data)}; taille={len(data)} octets; "
                        f"mtime={path.stat().st_mtime_ns}{archive_detail}. Aucun fichier extrait."),
                evidence=(f"sha256={sha256(data)}; flags={', '.join(flags) if flags else 'aucun'}; "
                          f"chaînes intéressantes={'; '.join(interesting) if interesting else 'aucune'}; "
                          f"archive={', '.join(members) if members else 'aucune'}"),
                source_module=self.name,
                remediation="Conserver l'artefact original et travailler sur une copie pour l'analyse approfondie.",
                steps=["Comparer le hash à l'original.", "Examiner le type, les chaînes et les métadonnées sans extraire ni exécuter l'artefact."],
            ))
