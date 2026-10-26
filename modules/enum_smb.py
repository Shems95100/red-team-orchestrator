"""
enum_smb.py — Phase enum : énumération SMB / Active Directory (Windows).

Se déclenche si la recon a trouvé du SMB (445/tcp) ou NetBIOS (139/tcp).
Orchestration d'outils existants :
  - nmap avec les scripts smb-os-discovery / smb-enum-shares / smb-enum-users
  - smbclient -L (listing de partages en session null) si disponible

C'est de l'énumération : on cartographie partages, OS et comptes exposés.
On n'altère rien. Scope-guardé + furtif + mappé ATT&CK.

Prérequis : nmap (scripts smb-*) ; smbclient optionnel (paquet smbclient).
"""

from __future__ import annotations

import re
import shutil
import subprocess

from core.context import Context, Finding
from core.scope import Scope, guard
from core.stealth import StealthProfile, get_profile
from modules.base import Module


class SmbEnum(Module):
    name = "smb-enum"
    phase = "enum"
    attack_refs = ["T1135", "T1087", "T1018"]  # Shares + Accounts + Remote System Discovery

    def __init__(self, stealth: StealthProfile | None = None):
        self.stealth = stealth or get_profile("quiet")

    def should_run(self, ctx: Context) -> bool:
        return any(
            svc.port in (445, 139) or svc.name in ("microsoft-ds", "netbios-ssn", "smb")
            for svc in ctx.all_services()
        )

    def run(self, ctx: Context, scope: Scope) -> None:
        hosts_with_smb = {
            svc.host for svc in ctx.all_services()
            if svc.port in (445, 139) or svc.name in ("microsoft-ds", "netbios-ssn", "smb")
        }
        for host in hosts_with_smb:
            guard(scope, host)
            self.stealth.sleep()
            self._nmap_smb(ctx, host)
            self._smbclient_shares(ctx, host)

    def _nmap_smb(self, ctx: Context, host: str) -> None:
        if not shutil.which("nmap"):
            ctx.log(self.name, "nmap introuvable, scripts SMB ignorés.")
            return
        scripts = "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode"
        cmd = ["nmap", "-p", "139,445", f"--script={scripts}",
               f"-T{self.stealth.nmap_timing}", "-Pn", host]
        ctx.log(self.name, f"nmap SMB : {' '.join(cmd)}")
        try:
            res = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            ctx.log(self.name, f"Timeout nmap SMB sur {host}")
            return
        out = res.stdout or ""
        self._parse_nmap_smb(ctx, host, out)

    def _parse_nmap_smb(self, ctx: Context, host: str, out: str) -> None:
        # OS Windows détecté
        m = re.search(r"OS:\s*(.+)", out)
        if m:
            ctx.add_finding(Finding(
                host=host, title="OS détecté via SMB",
                severity="info", detail=m.group(1).strip(),
                evidence="nmap smb-os-discovery", source_module=self.name,
                attack_refs=["T1018"],
            ))
        # Partages énumérés
        shares = re.findall(r"\\\\[^\\]+\\([^\s:]+)", out)
        shares = sorted(set(shares))
        if shares:
            ctx.add_finding(Finding(
                host=host, title=f"Partages SMB énumérés ({len(shares)})",
                severity="medium", detail="Partages : " + ", ".join(shares),
                evidence="nmap smb-enum-shares", source_module=self.name,
                attack_refs=["T1135"],
                remediation="Restreindre l'accès aux partages, désactiver les sessions null, "
                            "appliquer le principe du moindre privilège.",
            ))
        # Signing désactivé = classique en AD
        if re.search(r"message_signing:\s*disabled", out, re.IGNORECASE):
            ctx.add_finding(Finding(
                host=host, title="Signature SMB désactivée",
                severity="medium",
                detail="La signature SMB est désactivée — expose à des attaques de relais.",
                evidence="nmap smb-security-mode", source_module=self.name,
                remediation="Activer et imposer la signature SMB (SMB signing) sur les hôtes et le domaine.",
            ))

    def _smbclient_shares(self, ctx: Context, host: str) -> None:
        if not shutil.which("smbclient"):
            return  # optionnel
        self.stealth.sleep()
        cmd = ["smbclient", "-L", f"//{host}", "-N"]  # -N = session null (sans mot de passe)
        ctx.log(self.name, f"smbclient : {' '.join(cmd)}")
        try:
            res = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            return
        if "Sharename" in (res.stdout or ""):
            ctx.add_finding(Finding(
                host=host, title="Session SMB null autorisée",
                severity="high",
                detail="Un listing de partages est possible SANS authentification (session null).",
                evidence="smbclient -L -N", source_module=self.name,
                attack_refs=["T1135", "T1087"],
                remediation="Désactiver les sessions null / l'accès anonyme SMB "
                            "(RestrictAnonymous / RestrictNullSessAccess).",
            ))
