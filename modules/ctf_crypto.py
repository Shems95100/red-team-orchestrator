"""Offline identification of common CTF encodings and classical ciphers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import codecs
from pathlib import Path

from core.context import Context, Finding
from core.scope import Scope
from modules.base import Module
from modules.ctf_patterns import build_flag_pattern

MAX_ARTIFACT_BYTES = 512 * 1024


def _text_candidate(data: bytes) -> str:
    return data.decode("utf-8", "strict")


def _caesar(text: str, shift: int) -> str:
    output = []
    for char in text:
        if "a" <= char <= "z":
            output.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            output.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        else:
            output.append(char)
    return "".join(output)


class CryptoTriage(Module):
    """Tries bounded, common encodings locally; it never contacts a target."""

    name = "ctf-crypto-triage"
    phase = "vuln"

    def __init__(self, artifact_paths: list[str] | None = None, flag_prefix: str | None = None):
        self.artifact_paths = [Path(path) for path in artifact_paths or []]
        self.flag_re = build_flag_pattern(flag_prefix)

    def should_run(self, ctx: Context) -> bool:
        return bool(self.artifact_paths)

    def _candidates(self, data: bytes) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []
        try:
            candidates.append(("plain", _text_candidate(data)))
        except UnicodeDecodeError:
            pass

        compact = b"".join(data.split())
        if compact and len(compact) % 4 == 0:
            try:
                decoded = base64.b64decode(compact, validate=True)
                candidates.append(("base64", decoded.decode("utf-8", "strict")))
            except (binascii.Error, UnicodeDecodeError, ValueError):
                pass

        stripped = data.strip()
        if stripped and len(stripped) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+", stripped):
            try:
                candidates.append(("hex", bytes.fromhex(stripped.decode("ascii")).decode("utf-8", "strict")))
            except (UnicodeDecodeError, ValueError):
                pass

        try:
            text = _text_candidate(data)
        except UnicodeDecodeError:
            text = ""
        if text and len(text) <= MAX_ARTIFACT_BYTES:
            candidates.append(("rot13", codecs.decode(text, "rot_13")))
            for shift in range(1, 26):
                candidates.append((f"caesar-{shift}", _caesar(text, shift)))
        return candidates

    def run(self, ctx: Context, scope: Scope) -> None:
        for path in self.artifact_paths:
            try:
                data = path.read_bytes()
            except OSError as exc:
                ctx.log(self.name, f"Artefact illisible {path}: {exc}")
                continue
            if len(data) > MAX_ARTIFACT_BYTES:
                ctx.log(self.name, f"Artefact ignoré (limite 512 KiB dépassée): {path}")
                continue

            matches: list[str] = []
            for method, text in self._candidates(data):
                for flag in self.flag_re.findall(text):
                    entry = f"{method}: {flag}"
                    if entry not in matches:
                        matches.append(entry)
            digest = hashlib.sha256(data).hexdigest()
            ctx.add_finding(Finding(
                host="local-artifact",
                title=f"Crypto CTF : analyse hors ligne de {path.name}",
                severity="medium" if matches else "info",
                confidence="firm" if matches else "tentative",
                detail=(f"Artefact de {len(data)} octets; encodages simples et chiffre de César testés localement. "
                        f"Candidats de flag détectés: {len(matches)}."),
                evidence=f"sha256={digest}; candidats={'; '.join(matches[:10]) if matches else 'aucun'}",
                source_module=self.name,
                remediation="Confirmer le décodage avec les consignes et le format du challenge.",
                steps=["Vérifier le format et l'empreinte de l'artefact.", "Reproduire le décodage candidat hors ligne."],
            ))
