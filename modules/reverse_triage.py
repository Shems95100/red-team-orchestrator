"""Static, non-executing triage for reverse-engineering CTF artifacts."""

from __future__ import annotations

import struct
from pathlib import Path

from core.context import Context, Finding
from core.scope import Scope
from modules.artifact_analysis import identify_format, printable_strings, read_artifact, sha256
from modules.base import Module
from modules.ctf_patterns import build_flag_pattern


class ReverseTriage(Module):
    name = "ctf-reverse-triage"
    phase = "vuln"

    def __init__(self, artifact_paths: list[str] | None = None, flag_prefix: str | None = None):
        self.artifact_paths = [Path(path) for path in artifact_paths or []]
        self.flag_re = build_flag_pattern(flag_prefix)

    def should_run(self, ctx: Context) -> bool:
        return bool(self.artifact_paths)

    def _architecture(self, data: bytes) -> str:
        if data.startswith(b"\x7fELF") and len(data) >= 20:
            endian = "<" if data[5] == 1 else ">" if data[5] == 2 else ""
            if endian:
                machine = struct.unpack_from(endian + "H", data, 18)[0]
                names = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}
                bits = {1: "32-bit", 2: "64-bit"}.get(data[4], "unknown class")
                return f"{names.get(machine, f'ELF machine {machine}')}, {bits}"
        if data.startswith(b"MZ") and len(data) >= 0x40:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 6 <= len(data) and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
                names = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "ARM64"}
                return names.get(machine, f"PE machine 0x{machine:04x}")
        return "architecture not identified"

    def run(self, ctx: Context, scope: Scope) -> None:
        for path in self.artifact_paths:
            try:
                data = read_artifact(path)
            except (OSError, ValueError) as exc:
                ctx.log(self.name, f"Artefact ignoré {path}: {exc}")
                continue

            strings = printable_strings(data)
            flags = list(dict.fromkeys(self.flag_re.findall(data.decode("latin-1"))))[:10]
            clues = [value for value in strings if any(
                marker in value.lower() for marker in ("flag", "ctf", "password", "token", "http://", "https://")
            )][:15]
            fmt = identify_format(data)
            architecture = self._architecture(data)
            ctx.add_finding(Finding(
                host="local-artifact",
                title=f"Flag reverse trouvé dans {path.name}" if flags else f"Triage reverse statique : {path.name}",
                severity="medium" if flags else "info",
                confidence="firm",
                detail=f"Format={fmt}; architecture={architecture}; taille={len(data)} octets. Aucun code exécuté.",
                evidence=(f"sha256={sha256(data)}; flags={', '.join(flags) if flags else 'aucun'}; "
                          f"chaînes intéressantes={'; '.join(clues) if clues else 'aucune'}"),
                source_module=self.name,
                remediation="Analyser le binaire dans un environnement isolé et ne jamais l'exécuter sur l'hôte de travail.",
                steps=["Vérifier le format et l'architecture identifiés.", "Examiner les chaînes statiques et les références au flag."],
            ))
