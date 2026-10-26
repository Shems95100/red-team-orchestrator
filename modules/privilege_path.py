"""privilege_path.py — privilege-path planning for enterprise environments.

This is the next safe layer after identity discovery: it models the likely route
from exposed AD / SMB / WinRM services to privileged access. It never performs
credential theft, lateral movement, or service disruption; it only produces a
mission-grade recommendation and evidence trail in the authorized context.
"""

from __future__ import annotations

from core.context import Context, Finding
from core.scope import Scope, guard
from core.stealth import StealthProfile, get_profile
from modules.base import Module


class PrivilegePath(Module):
    """Map the likely privileged access pathway from exposed Windows surface."""

    name = "privilege-path"
    phase = "post"
    attack_refs = ["T1069", "T1087", "T1482", "T1021.002", "T1021.006", "T1078"]
    min_severity = "high"

    def __init__(self, stealth: StealthProfile | None = None):
        self.stealth = stealth or get_profile("quiet")

    def should_run(self, ctx: Context) -> bool:
        services = ctx.all_services()
        if not services:
            return False

        domain_surface = any(
            svc.port in {88, 389, 636, 3268, 3269}
            or (svc.name or "").lower() in {"kerberos", "ldap", "ldaps"}
            for svc in services
        )
        admin_surface = any(
            svc.port in {445, 5985, 5986, 3389}
            or (svc.name or "").lower() in {"microsoft-ds", "wsman", "winrm", "rdp"}
            for svc in services
        )
        if not domain_surface or not admin_surface:
            return False

        hosts = {svc.host for svc in services}
        return any(
            any(svc.port in {88, 389, 636, 3268, 3269} for svc in ctx.hosts.get(host, ctx.add_host(host)).services)
            and any(svc.port in {445, 5985, 5986, 3389} for svc in ctx.hosts.get(host, ctx.add_host(host)).services)
            for host in hosts
        )

    def run(self, ctx: Context, scope: Scope) -> None:
        for host in sorted(ctx.hosts):
            guard(scope, host)
            self.stealth.sleep()

            host_services = ctx.hosts[host].services
            domain_ports = sorted({svc.port for svc in host_services if svc.port in {88, 389, 636, 3268, 3269} or (svc.name or "").lower() in {"kerberos", "ldap", "ldaps"}})
            admin_ports = sorted({svc.port for svc in host_services if svc.port in {445, 5985, 5986, 3389} or (svc.name or "").lower() in {"microsoft-ds", "wsman", "winrm", "rdp"}})

            if not domain_ports or not admin_ports:
                continue

            ctx.add_finding(
                Finding(
                    host=host,
                    title="Chemin de privilège probable : surface AD + administration exposée",
                    severity="critical",
                    confidence="firm",
                    detail=(
                        "Le système expose à la fois les services d’authentification / annuaire et les surfaces de administration "
                        "Windows. La corrélation de ces services suggère un chemin réaliste vers un accès privilégié dans un cadre "
                        "AD ou Windows maîtrisé; cette analyse est exclusivement d’aide à la décision et ne lance aucun mouvement actif."
                    ),
                    evidence=f"domain={domain_ports}; admin={admin_ports}",
                    source_module=self.name,
                    attack_refs=self.attack_refs,
                    remediation=(
                        "Valider le rôle de la machine dans le domaine, limiter le flux d’authentification vers la surface administrative, "
                        "et restreindre strictement tout accès de privilège à des comptes explicitement autorisés."
                    ),
                    steps=[
                        "Identifier le rôle de la machine et le niveau de confiance associé.",
                        "Vérifier si les comptes de service et les partages administratifs restent restreints.",
                        "Confirmer les chemins de délégation / privilèges avant toute action de mission.",
                        "Limiter toute opération de collecte ou d’escalade à l’autorisation écrite et au périmètre validé.",
                    ],
                )
            )

            if 445 in admin_ports or 5985 in admin_ports or 5986 in admin_ports:
                ctx.add_finding(
                    Finding(
                        host=host,
                        title="Voie d’escalade probable via SMB / WinRM / administration distante",
                        severity="high",
                        confidence="firm",
                        detail=(
                            "La présence simultanée de SMB et de services d’administration Windows augmente la probabilité d’une route "
                            "d’accès privilégié ou de mouvement latéral une fois la preuve de mission et l’autorisation vérifiées."
                        ),
                        evidence=f"remote-admin={admin_ports}",
                        source_module=self.name,
                        attack_refs=["T1021.002", "T1021.006", "T1078"],
                        remediation="Limiter les interfaces de gestion, contrôler les comptes de service et verrouiller les exports SMB sensibles.",
                        steps=[
                            "Valider la politique d’accès réseau et les comptes liés.",
                            "Exiger une preuve explicite avant toute action d’escalade.",
                            "Rester dans le périmètre de mission et le cadre autorisé.",
                        ],
                    )
                )
