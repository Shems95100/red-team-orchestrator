#!/usr/bin/env python3
"""
ctf_crypto.py — Boîte à outils crypto / encodage pour CTF.

Catégorie "crypto" d'un CTF : tu lui donnes une chaîne mystérieuse trouvée dans
un challenge, il essaie automatiquement les transformations classiques et
surligne tout ce qui ressemble à un flag.

Ce n'est PAS un outil d'attaque réseau : il travaille uniquement sur du texte
que TU lui fournis (une chaîne, un fichier). 100 % hors-ligne, sans cible.

Usage :
    python ctf_crypto.py "SGVsbG8gd29ybGQ="            # une chaîne
    python ctf_crypto.py --file challenge.txt           # un fichier
    python ctf_crypto.py --flag "HTB{" "...."           # format de flag perso
"""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import re
import string
import sys

DEFAULT_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}]{1,}\}")  # ex: flag{...}, HTB{...}


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return printable / len(b)


def _show(label: str, value: str, flag_re: re.Pattern, results: list) -> None:
    """Affiche une transformation et marque si elle contient un flag."""
    hit = flag_re.search(value)
    mark = "  <<< FLAG POSSIBLE" if hit else ""
    # On tronque pour l'affichage mais on garde la détection sur le texte complet.
    shown = value if len(value) <= 120 else value[:117] + "..."
    print(f"[{label:14}] {shown}{mark}")
    if hit:
        results.append((label, hit.group(0)))


# --------------------------------------------------------------------------- #
# Décodeurs
# --------------------------------------------------------------------------- #
def try_base64(s: str):
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
        if _printable_ratio(raw) > 0.85:
            return raw.decode("utf-8", "replace")
    except Exception:
        pass
    return None


def try_base32(s: str):
    try:
        raw = base64.b32decode(s + "=" * (-len(s) % 8), casefold=True)
        if _printable_ratio(raw) > 0.85:
            return raw.decode("utf-8", "replace")
    except Exception:
        pass
    return None


def try_hex(s: str):
    t = s.strip().replace(" ", "")
    try:
        raw = binascii.unhexlify(t)
        if _printable_ratio(raw) > 0.85:
            return raw.decode("utf-8", "replace")
    except Exception:
        pass
    return None


def try_url(s: str):
    from urllib.parse import unquote
    out = unquote(s)
    return out if out != s else None


def try_rot_all(s: str, flag_re, results):
    """Affiche les 25 rotations de César (ROT1..ROT25)."""
    for n in range(1, 26):
        rotated = "".join(
            chr((ord(c) - base_ + n) % 26 + base_) if c.isalpha() else c
            for c in s
            for base_ in [ord("a") if c.islower() else ord("A")]
        )
        if flag_re.search(rotated):
            _show(f"ROT{n}", rotated, flag_re, results)


def try_atbash(s: str):
    def swap(c):
        if c.islower():
            return chr(ord("z") - (ord(c) - ord("a")))
        if c.isupper():
            return chr(ord("Z") - (ord(c) - ord("A")))
        return c
    return "".join(swap(c) for c in s)


def try_xor_single(s: str, flag_re, results):
    """Brute single-byte XOR si l'entrée est du hex (classique CTF)."""
    t = s.strip().replace(" ", "")
    try:
        raw = binascii.unhexlify(t)
    except Exception:
        return
    for key in range(256):
        dec = bytes(b ^ key for b in raw)
        if _printable_ratio(dec) > 0.9:
            txt = dec.decode("utf-8", "replace")
            if flag_re.search(txt):
                _show(f"XOR 0x{key:02x}", txt, flag_re, results)


def try_binary(s: str):
    bits = re.findall(r"[01]{8}", s)
    if len(bits) >= 2:
        try:
            return "".join(chr(int(b, 2)) for b in bits)
        except Exception:
            return None
    return None


def try_decimal(s: str):
    nums = re.findall(r"\d{1,3}", s)
    if len(nums) >= 3 and all(0 <= int(n) < 256 for n in nums):
        try:
            return "".join(chr(int(n)) for n in nums)
        except Exception:
            return None
    return None


MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def try_morse(s: str):
    if not re.fullmatch(r"[.\-/ ]+", s.strip()):
        return None
    words = s.strip().split("/")
    out = []
    for w in words:
        out.append("".join(MORSE.get(sym, "?") for sym in w.split()))
    return " ".join(out).strip() or None


# --------------------------------------------------------------------------- #
# Identification de hash (pour la catégorie "crack me")
# --------------------------------------------------------------------------- #
HASH_PATTERNS = [
    (re.compile(r"^[a-f0-9]{32}$", re.I), "MD5 ou NTLM (32 hex)"),
    (re.compile(r"^[a-f0-9]{40}$", re.I), "SHA-1 (40 hex)"),
    (re.compile(r"^[a-f0-9]{64}$", re.I), "SHA-256 (64 hex)"),
    (re.compile(r"^[a-f0-9]{128}$", re.I), "SHA-512 (128 hex)"),
    (re.compile(r"^\$2[aby]\$\d{2}\$.{53}$"), "bcrypt"),
    (re.compile(r"^\$1\$.{0,8}\$.{22}$"), "md5crypt"),
    (re.compile(r"^\$6\$.{0,16}\$.{86}$"), "sha512crypt"),
]


def identify_hash(s: str):
    s = s.strip()
    return [name for pat, name in HASH_PATTERNS if pat.match(s)]


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #
def solve(data: str, flag_re: re.Pattern) -> None:
    results: list = []
    print(f"\n=== Entrée ({len(data)} caractères) ===")
    print(data if len(data) <= 200 else data[:197] + "...")

    # Le flag est peut-être déjà en clair.
    _show("clair", data, flag_re, results)

    # Hash ?
    hashes = identify_hash(data)
    if hashes:
        print(f"[hash          ] Ressemble à : {', '.join(hashes)} "
              f"-> à cracker (ex. john/hashcat avec un wordlist, ou base en ligne)")

    print("\n=== Décodages tentés ===")
    for label, fn in [
        ("base64", try_base64), ("base32", try_base32), ("hex", try_hex),
        ("url", try_url), ("atbash", try_atbash), ("binary", try_binary),
        ("decimal", try_decimal), ("morse", try_morse), ("rot13", lambda x: codecs.encode(x, "rot13")),
    ]:
        try:
            out = fn(data)
        except Exception:
            out = None
        if out:
            _show(label, out, flag_re, results)

    # Rotations de César + XOR (affichent seulement si flag trouvé).
    try_rot_all(data, flag_re, results)
    try_xor_single(data, flag_re, results)

    print("\n=== Bilan ===")
    if results:
        for label, flag in results:
            print(f"  ✔ FLAG via {label} : {flag}")
    else:
        print("  Aucun flag auto-détecté. Essaie : --flag <préfixe>, ou vérifie")
        print("  que l'entrée n'est pas un chiffrement nécessitant une clé (Vigenère, RSA...).")


def main() -> None:
    p = argparse.ArgumentParser(description="Boîte à outils crypto/encodage pour CTF (hors-ligne).")
    p.add_argument("data", nargs="?", help="La chaîne à analyser")
    p.add_argument("--file", help="Lire l'entrée depuis un fichier")
    p.add_argument("--flag", default=None, help="Préfixe de flag (ex: HTB{, FLAG{) pour cibler la détection")
    args = p.parse_args()

    if args.file:
        data = open(args.file, encoding="utf-8", errors="replace").read().strip()
    elif args.data:
        data = args.data
    else:
        data = sys.stdin.read().strip()

    if not data:
        p.error("Aucune donnée fournie (chaîne, --file, ou stdin).")

    flag_re = re.compile(re.escape(args.flag) + r"[^}]*\}") if args.flag else DEFAULT_FLAG_RE
    solve(data, flag_re)


if __name__ == "__main__":
    main()
