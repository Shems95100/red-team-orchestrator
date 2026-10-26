"""enum_winrm.py — Windows remote management / RDP discovery.

This module expands the enterprise surface by recognizing Windows management
ports and exposing them as reachable pathways for validated, authorized activity
within a lab environment. It stays passive: enumeration only, no remote execution.
"""

from __future__ import annotations

from core.context import Context, Finding
from core.scope import Scope, guard
from core.stealth import StealthProfile, get_profile
from modules.base import Module


class WinRmEnum(Module):
    name = "winrm-enum"
    phase = "enum"
    attack_refs = ["T1021.006", "T1078", "T1059.001"]

    def __init__(self, stealth: StealthProfile | None = None):
        self.stealth = stealth or get_profile("ghost")

    def should_run(self, ctx: Context) -> bool:
        candidates = {135, 3389, 5985, 5986, 47001, 49152, 49153}
        names = {"wsman", "winrm", "rdp", "ms-wbt-server", "rpcbind", "microsoft-ds"}
        return any(
            svc.port in candidates or (svc.name or "").lower() in names
            for svc in ctx.all_services()
        )

    def run(self, ctx: Context, scope: Scope) -> None:
        hosts = {
            svc.host
            for svc in ctx.all_services()
            if svc.port in {135, 3389, 5985, 5986, 47001, 49152, 49153}
            or (svc.name or "").lower() in {"wsman", "winrm", "rdp", "ms-wbt-server", "rpcbind", "microsoft-ds"}
        }

        for host in sorted(hosts):
            guard(scope, host)
            self.stealth.sleep()

            ports = sorted({svc.port for svc in ctx.all_services() if svc.host == host})
            winrm_ports = [p for p in ports if p in {5985, 5986}]
            rdp_ports = [p for p in ports if p in {3389}]

            if winrm_ports:
                ctx.add_finding(
                    Finding(
                        host=host,
                        title="Windows Remote Management exposé",
                        severity="high",
                        confidence="firm",
                        detail=(
                            "Des ports WinRM / WSMan sont visibles. Cette surface est particulièrement utile pour "
                            "l’authentification Windows ou la gestion distante dans un environnement d’entreprise."
                        ),
                        evidence=f"ports WinRM observés: {winrm_ports}",
                        source_module=self.name,
                        attack_refs=self.attack_refs,
                        remediation=(
                            "Restreindre l’accès à WinRM au strict périmètre autorisé, sécuriser les comptes Windows, "
                            "et contrôler la gestion distante via firewalls et politiques de groupe."
                        ),
                        steps=[
                            "Identifier la machine Windows sous-jacente.",
                            "Vérifier le service WinRM et les ports exposés.",
                            "Confirmer la validation et les permissions de mission avant toute authentification ciblée.",
                        ],
                    )
                )

            if rdp_ports:
                ctx.add_finding(
                    Finding(
                        host=host,
                        title="Service RDP visible",
                        severity="medium",
                        confidence="firm",
                        detail=(
                            "Le service RDP est visible. En environnement AD, cette exposition augmente fortement le potentiel "
                            "d’accès distant et de mouvement latéral si le périmètre n’est pas strictement contrôlé."
                        ),
                        evidence=f"ports RDP observés: {rdp_ports}",
                        source_module=self.name,
                        attack_refs=["T1021.001"],
                        remediation=(
                            "Limiter l’accès RDP, utiliser MFA ou JIT, et restreindre les règles de pare-feu à des hôtes autorisés."
                        ),
                        steps=[
                            "Identifier le rôle de la machine et son placement dans le réseau.",
                            "Valider l’accès spécifié par la mission.",
                            "Éviter tout mouvement latéral hors périmètre.",
                        ],
                    )
                )

            if winrm_ports and rdp_ports:
                ctx.add_finding(
                    Finding(
                        host=host,
                        title="Surface Windows d’accès distant élevée",
                        severity="critical",
                        confidence="firm",
                        detail=(
                            "WinRM + RDP sur la même cible indique une surface d’administration Windows très utile pour la "
                            "gestion, l’accès distant et les mouvements de privilèges dans un réseau d’entreprise."
                        ),
                        evidence=f"WinRM {winrm_ports} + RDP {rdp_ports}",
                        source_module=self.name,
                        attack_refs=["T1021.006", "T1021.001"],
                        remediation=(
                            "Sécuriser la surface Windows avec segmentation, accès JIT, MFA et politiques de gestion."
                        ),
                        steps=[
                            "Prioriser cette cible selon le score de risque métier.",
                            "Valider le besoin exact d’accès.",
                            "Ne lancer qu’une action explicitement autorisée et documentée.",
                        ],
                    )
                )
