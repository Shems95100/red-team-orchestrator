"""enum_identity.py — identity and privilege-path discovery for enterprise targets.

This layer models the next logical step after AD/SMB/WinRM discovery: determine
whether the exposed services suggest a likely path to privileged access in a
controlled environment (domain admin exposure, admin shares, Kerberos/LDAP path,
admin-side service surfaces). It remains strictly passive and evidence-first.
"""

from __future__ import annotations

from core.context import Context, Finding
from core.scope import Scope, guard
from core.stealth import StealthProfile, get_profile
from modules.base import Module


class IdentityEnum(Module):
    name = "identity-enum"
    phase = "enum"
    attack_refs = ["T1069", "T1087", "T1482", "T1021.006", "T1078"]

    def __init__(self, stealth: StealthProfile | None = None):
        self.stealth = stealth or get_profile("ghost")

    def should_run(self, ctx: Context) -> bool:
        has_windows_surface = any(
            svc.port in {445, 139, 389, 636, 88, 5985, 5986, 3389}
            or (svc.name or "").lower() in {"microsoft-ds", "ldap", "ldaps", "kerberos", "wsman", "winrm", "rdp"}
            for svc in ctx.all_services()
        )
        if not has_windows_surface:
            return False

        has_domain_signal = any(
            svc.port in {389, 636, 88, 3268, 3269}
            or (svc.name or "").lower() in {"ldap", "ldaps", "kerberos"}
            for svc in ctx.all_services()
        )
        has_admin_signal = any(
            svc.port in {445, 5985, 5986, 3389}
            or (svc.name or "").lower() in {"microsoft-ds", "wsman", "winrm", "rdp"}
            for svc in ctx.all_services()
        )
        return has_domain_signal and has_admin_signal

    def run(self, ctx: Context, scope: Scope) -> None:
        targets = {
            svc.host
            for svc in ctx.all_services()
            if svc.port in {445, 139, 389, 636, 88, 5985, 5986, 3389, 3268, 3269}
            or (svc.name or "").lower() in {"microsoft-ds", "ldap", "ldaps", "kerberos", "wsman", "winrm", "rdp"}
        }

        for host in sorted(targets):
            guard(scope, host)
            self.stealth.sleep()

            svc_ports = sorted({svc.port for svc in ctx.all_services() if svc.host == host})
            domain_ports = [p for p in svc_ports if p in {88, 389, 636, 3268, 3269}]
            admin_ports = [p for p in svc_ports if p in {445, 5985, 5986, 3389}]

            if domain_ports and admin_ports:
                ctx.add_finding(
                    Finding(
                        host=host,
                        title="Chemin d’accès privilégié potentiel détecté",
                        severity="critical",
                        confidence="firm",
                        detail=(
                            "La cible expose simultanément des services d’authentification / annuaire et des surfaces "
                            "d’administration Windows. Cela suggère un chemin plausible vers des privilèges élevés "
                            "dans un environnement AD bien structuré."
                        ),
                        evidence=f"domain={domain_ports}; admin={admin_ports}",
                        source_module=self.name,
                        attack_refs=self.attack_refs,
                        remediation=(
                            "Valider la présence d’authentification AD, restreindre l’accès aux services d’administration, "
                            "et limiter les chemins de privilèges aux comptes explicitement approuvés."
                        ),
                        steps=[
                            "Confirmer le rôle exact de la machine dans le domaine.",
                            "Identifier les comptes et services exposés.",
                            "Contrôler strictement tout accès administratif ou authentifié.",
                        ],
                    )
                )

            if 445 in svc_ports or 139 in svc_ports:
                ctx.add_finding(
                    Finding(
                        host=host,
                        title="Surface SMB / partages d’administration potentiellement sensible",
                        severity="high",
                        confidence="firm",
                        detail=(
                            "La présence de SMB/NetBIOS sur une cible AD ou Windows est souvent associée à des partages "
                            "administratifs, à des comptes ou à des chemins de délégation de privilèges."
                        ),
                        evidence=f"SMB exposure on ports {sorted([p for p in svc_ports if p in {445, 139}])}",
                        source_module=self.name,
                        attack_refs=["T1135", "T1021.002"],
                        remediation=(
                            "Restreindre les partages administratifs, verrouiller les sessions null, et piloter les accès par politique AD stricte."
                        ),
                        steps=[
                            "Identifier les partages exposés.",
                            "Valider la portée du privilège associé.",
                            "Limiter toute action à l’autorisation écrite de la mission.",
                        ],
                    )
                )
