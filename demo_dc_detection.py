#!/usr/bin/env python3
"""
demo_dc_detection.py — Donne au bot un log nmap EXISTANT et lance l'analyse AD
(module enum_ad) SANS toucher au reseau.

But : prouver que le Red Team Orchestrator identifie seul le controleur de
domaine a partir d'une simple sortie nmap — la question exacte du challenge
Root-Me "AD Recon - Enumeration de ports".

Usage : python demo_dc_detection.py [chemin_log]   (defaut: nmap_rootme_local.log)
"""
from __future__ import annotations

import ipaddress
import re
import sys

from core.context import Context, Service
from core.scope import Scope
from core.stealth import get_profile
from modules.enum_ad import AdEnum

HOST_RE = re.compile(r"Nmap scan report for (\S+)")
PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)")


def parse_nmap_log(path):
    """Transforme un log nmap texte en Context (ce que la phase recon remplit)."""
    ctx = Context()
    current = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = HOST_RE.search(line)
            if m:
                current = m.group(1)
                ctx.add_host(current)
                continue
            pm = PORT_RE.match(line.strip())
            if pm and current:
                ctx.hosts[current].services.append(
                    Service(host=current, port=int(pm.group(1)),
                            proto=pm.group(2), name=pm.group(3))
                )
    return ctx


def strip_accents(s):
    import unicodedata
    return "".join(c for c in unicodedata.normalize("NFD", s.lower())
                   if unicodedata.category(c) != "Mn")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "nmap_rootme_local.log"
    ctx = parse_nmap_log(path)

    print("\n[*] Log importe dans le bot : %s" % path)
    print("[*] %d hote(s) charge(s) :" % len(ctx.hosts))
    for host in ctx.hosts.values():
        ports = ", ".join(str(s.port) for s in host.services)
        print("      - %-15s ports: %s" % (host.address, ports))

    # Perimetre autorise : le /24 du lab (IP litterales -> pas de resolution DNS).
    scope = Scope(networks=[ipaddress.ip_network("192.168.1.0/24")])

    print("\n[*] Module enum_ad (analyse AD, 100% passive) en cours...\n")
    AdEnum(stealth=get_profile("normal")).run(ctx, scope)

    dc = [f for f in ctx.findings if "controleur de domaine" in strip_accents(f.title)]
    print("\n" + "=" * 62)
    print("VERDICT DU BOT")
    print("=" * 62)
    if dc:
        for f in dc:
            print("  [%-8s] %-15s %s" % (f.severity.upper(), f.host, f.title))
            print("             preuve : %s" % f.evidence)
        print("\n  >>> Controleur de domaine identifie : %s" % dc[0].host)
        print("      Reponse du challenge Root-Me : 192.168.1.20 (option B)")
    else:
        print("  Aucun DC detecte.")
    print()


if __name__ == "__main__":
    main()
