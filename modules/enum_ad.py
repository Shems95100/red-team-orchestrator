"""enum_ad.py — Active Directory / LDAP discovery for enterprise targets.

This module models the next level of internal recon: DC indicators, Kerberos,
LDAP, SMB + AD port correlation. It remains strictly passive and scope-guarded,
providing high-value evidence without performing destructive actions.
"""

from __future__ import annotations

from core.context import Context, Finding
from core.scope import Scope, guard
from core.stealth import StealthProfile, get_profile
from modules.base import Module


class AdEnum(Module):
    name = "ad-enum"
    phase = "enum"
    attack_refs = ["T1018", "T1069", "T1482", "T1046"]

    def __init__(self, stealth: StealthProfile | None = None):
        self.stealth = stealth or get_profile("ghost")

    def should_run(self, ctx: Context) -> bool:
        candidates = {
            88, 389, 636, 3268, 3269, 445, 139, 464, 593, 8080
        }
        names = {"ldap", "ldaps", "kerberos", "kpasswd", "microsoft-ds", "smb", "netbios-ssn"}
        return any(
            svc.port in candidates or (svc.name or "").lower() in names
            for svc in ctx.all_services()
        )

    def run(self, ctx: Context, scope: Scope) -> None:
        hosts = {
            svc.host
            for svc in ctx.all_services()
            if svc.port in {88, 389, 636, 3268, 3269, 445, 139, 464, 593}
            or (svc.name or "").lower() in {"ldap", "ldaps", "kerberos", "kpasswd", "microsoft-ds", "smb", "netbios-ssn"}
        }

        for host in sorted(hosts):
            guard(scope, host)
            self.stealth.sleep()

            ports = sorted({svc.port for svc in ctx.all_services() if svc.host == host})
            ad_ports = [p for p in ports if p in {88, 389, 636, 3268, 3269, 464}]
            smb_ports = [p for p in ports if p in {445, 139}]

            if ad_ports:
                ctx.add_finding(
                    Finding(
                        host=host,
                        title="Services d’annuaire Active Directory exposés",
                        severity="high" if any(p in {389, 636, 3268, 3269} for p in ad_ports) else "medium",
                        confidence="firm",
                        detail=(
                            "Des services LDAP / Kerberos / DC ou leurs équivalents sont visibles. "
                            "Cette combinaison est hautement indicative d’une présence AD."
                        ),
                        evidence=f"ports AD observés: {ad_ports}",
                        source_module=self.name,
                        attack_refs=self.attack_refs,
                        remediation=(
                            "Limiter l’exposition des ports LDAP/Kerberos, sécuriser les contrôleurs de domaine, "
                            "et restreindre l’accès aux services d’annuaire au strict nécessaire."
                        ),
                        steps=[
                            "Identifier le contrôleur de domaine exact.",
                            "Vérifier les services Kerberos/LDAP exposés.",
                            "Confirmer le périmètre autorisé avant toute exploitation ou authentification ciblée.",
                        ],
                    )
                )

            if smb_ports and ad_ports:
                ctx.add_finding(
                    Finding(
                        host=host,
                        title="Candidat contrôleur de domaine / environnement AD détecté",
                        severity="critical",
                        confidence="firm",
                        detail=(
                            "Les services SMB et LDAP/Kerberos cohabitent sur la même cible — cela correspond à un "
                            "modèle typique de contrôleur de domaine ou de machine AD importante."
                        ),
                        evidence=f"SMB {smb_ports} + AD {ad_ports}",
                        source_module=self.name,
                        attack_refs=["T1018", "T1482"],
                        remediation=(
                            "Valider la présence exacte du DC, sécuriser les accès SMB/LDAP, et contrôler strictement "
                            "toute exploitation authentifiée ou d’élévation de privilèges."
                        ),
                        steps=[
                            "Confirmer l’authenticité du contrôleur de domaine.",
                            "Identifier les services exposés et les comptes associés.",
                            "Limiter toute extension de la chaîne à un périmètre explicitement autorisé.",
                        ],
                    )
                )
