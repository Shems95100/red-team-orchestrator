"""
recon_nmap.py — Phase recon : orchestration de nmap.

Le bot ne réinvente pas le scan : il pilote nmap (-sV pour détecter les
services et versions), parse le XML de sortie, et remplit le Context avec les
hôtes/services trouvés. Les phases suivantes s'appuient sur ça.

Prérequis : nmap installé sur la machine (`sudo apt install nmap`).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from core.context import Context, Service
from core.scope import Scope, guard
from core.stealth import StealthProfile, get_profile
from modules.base import Module


class NmapRecon(Module):
    name = "nmap-recon"
    phase = "recon"
    attack_refs = ["T1595", "T1046"]  # Active Scanning + Network Service Discovery

    def __init__(self, stealth: StealthProfile | None = None, extra_args: list[str] | None = None):
        # -sV : détection de version. Le reste (timing, top-ports, intensité,
        # scan-delay...) vient du profil de furtivité : en mode "ghost" on passe
        # en low-and-slow pour rester sous les seuils d'alerte de la blue team.
        self.stealth = stealth or get_profile("quiet")
        self.base_args = ["-sV", *self.stealth.nmap_args()]
        self.extra_args = extra_args or []

    def should_run(self, ctx: Context) -> bool:
        # La recon tourne tant qu'on n'a pas encore de services connus.
        return not ctx.all_services()

    def run(self, ctx: Context, scope: Scope) -> None:
        if not shutil.which("nmap"):
            ctx.log(self.name, "nmap introuvable. Installe-le : sudo apt install nmap")
            return

        port_scope = ",".join(str(port) for port in sorted(scope.allowed_ports)) if scope.allowed_ports else f"top-{self.stealth.top_ports}"
        ctx.log(self.name, f"Profil : {self.stealth.name} (timing -T{self.stealth.nmap_timing}, ports={port_scope})")
        for address in list(ctx.hosts.keys()):
            guard(scope, address)  # refuse si hors périmètre
            self._scan_host(ctx, address, scope)
            self.stealth.sleep()   # pause furtive avant la cible suivante

    def _scan_command(self, address: str, scope: Scope, xml_path: Path | None = None) -> list[str]:
        args = list(self.base_args)
        if scope.allowed_ports:
            top_ports_index = args.index("--top-ports") if "--top-ports" in args else -1
            if top_ports_index >= 0:
                del args[top_ports_index:top_ports_index + 2]
        cmd = ["nmap", *args, *self.extra_args]
        if scope.allowed_ports:
            cmd.extend(["-p", ",".join(str(port) for port in sorted(scope.allowed_ports))])
        if xml_path is not None:
            cmd.extend(["-oX", str(xml_path)])
        cmd.append(address)
        return cmd

    def _scan_host(self, ctx: Context, address: str, scope: Scope) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "scan.xml"
            cmd = self._scan_command(address, scope, xml_path)
            ctx.log(self.name, f"Scan : {' '.join(cmd)}")
            try:
                subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=600)
            except subprocess.TimeoutExpired:
                ctx.log(self.name, f"Timeout sur {address}")
                return
            if not xml_path.exists():
                ctx.log(self.name, f"Pas de sortie XML pour {address}")
                return
            self._parse(ctx, address, xml_path)

    def _parse(self, ctx: Context, address: str, xml_path: Path) -> None:
        root = ET.parse(xml_path).getroot()
        host = ctx.add_host(address)
        count = 0
        for host_el in root.findall("host"):
            # OS best-guess si dispo
            for osmatch in host_el.findall("./os/osmatch"):
                host.os_guess = osmatch.get("name", "")
                break
            for port_el in host_el.findall("./ports/port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port_el.get("portid", "0"))
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                svc = Service(
                    host=address,
                    port=portid,
                    proto=proto,
                    name=(svc_el.get("name", "") if svc_el is not None else ""),
                    product=(svc_el.get("product", "") if svc_el is not None else ""),
                    version=(svc_el.get("version", "") if svc_el is not None else ""),
                )
                host.services.append(svc)
                count += 1
                ctx.log(self.name, f"Ouvert {address}:{portid} -> {svc.name} {svc.product} {svc.version}".rstrip())
        ctx.log(self.name, f"{count} service(s) ouvert(s) sur {address}")
