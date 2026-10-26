#!/usr/bin/env python3
"""
main.py — Point d'entrée du Red Team Orchestrator.

Usage :
    python main.py --scope scope.yaml --targets 192.168.56.101 10.0.0.5
    python main.py --scope scope.yaml --targets-file cibles.txt --nvd-key XXXX

Le bot :
  1. charge le périmètre autorisé (scope.yaml) ;
  2. filtre les cibles hors périmètre ;
  3. déroule recon -> vuln -> exploit -> report en s'adaptant à ce qu'il trouve ;
  4. écrit rapport.md.

C'est l'endroit où tu ENREGISTRES tes modules : ajoute une ligne dans build_modules().
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from core.engine import Engine
from core.exploit_policy import ExploitPolicy
from core.scope import Scope
from core.stealth import get_profile
from modules.audit_notice import AuditNotice
from modules.base import Module
from modules.cve_lookup import CveLookup
from modules.check_default_creds import DefaultCredsHTTP
from modules.enum_http import HttpEnum
from modules.enum_smb import SmbEnum
from modules.enum_ad import AdEnum
from modules.enum_winrm import WinRmEnum
from modules.enum_identity import IdentityEnum
from modules.privilege_path import PrivilegePath
from modules.exploit_ssh import ExploitSSH
from modules.exploit_web import ExploitWeb
from modules.investigation_module import InvestigationModule
from modules.post_exploit import PostExploit
from modules.recon_nmap import NmapRecon
from modules.osint import OsintRecon
from modules.report_module import ReportModule


def setup_logging(verbose: bool, log_file: str | None) -> None:
    """Configure le logging du framework (logger 'rto').

    Par défaut : rendu identique à avant (juste le message), sur la sortie
    standard. Avec --verbose : horodatage + niveau. Avec --log-file : écrit
    aussi dans un fichier (utile pour garder une trace d'une mission).
    """
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s %(levelname)s %(message)s" if verbose else "%(message)s"
    formatter = logging.Formatter(fmt)

    logger = logging.getLogger("rto")
    logger.setLevel(level)
    logger.handlers.clear()   # évite les doublons si appelé deux fois

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(fh)


def resolve_runtime_profile(args: argparse.Namespace) -> None:
    """Consolide la configuration de mission pour le mode automatique, démonstration et validation."""
    if getattr(args, "auto", False):
        args.mode = "exploit"
        args.allow_exploit = True
        args.stealth = "quiet"
        args.require_evidence = False
        args.exploit_min_severity = "low"
        args.dry_run = False

    if getattr(args, "demo", False):
        args.mode = "exploit"
        args.allow_exploit = True
        args.stealth = "quiet"
        args.require_evidence = False
        args.exploit_min_severity = "low"
        args.dry_run = False


def build_modules(
    nvd_key: str | None,
    report_path: str,
    stealth_name: str,
    allow_exploit: bool | None = None,
    dry_run: bool = False,
    exploit_min_severity: str = "low",
    require_evidence: bool = False,
    mode: str | None = None,
    allow_data_access: bool = False,
    allow_service_shutdown: bool = False,
    allow_web_shutdown: bool = False,
) -> list[Module]:
    """Catalogue des capacités du bot. Ajoute tes modules ici."""
    stealth = get_profile(stealth_name)
    resolved_mode = mode or ("exploit" if allow_exploit is None or allow_exploit else "audit")
    resolved_allow = resolved_mode != "audit" and (
        bool(allow_exploit)
        or resolved_mode == "exploit"
        or allow_data_access
        or allow_service_shutdown
        or allow_web_shutdown
    )
    resolved_require_evidence = require_evidence and not resolved_allow
    policy = ExploitPolicy(
        min_severity=exploit_min_severity,
        require_evidence=resolved_require_evidence,
        allow_exploit=resolved_allow,
        allow_data_access=allow_data_access,
        allow_service_shutdown=allow_service_shutdown,
        allow_web_shutdown=allow_web_shutdown,
    )

    modules: list[Module] = [
        NmapRecon(stealth=stealth),
        OsintRecon(),                          # phase recon (OSINT passif)            # phase recon (furtive)
        HttpEnum(stealth=stealth, safe_mode=resolved_mode == "audit"),
        SmbEnum(stealth=stealth),              # phase enum (SMB / Active Directory)
        AdEnum(stealth=stealth),               # phase enum (AD / LDAP / Kerberos)
        WinRmEnum(stealth=stealth),            # phase enum (Windows remote management / RDP)
        IdentityEnum(stealth=stealth),         # phase enum (identity / privilege paths / admin surfaces)
        PrivilegePath(stealth=stealth),        # phase post (map likely enterprise privilege route)
        CveLookup(api_key=nvd_key),            # phase vuln
        InvestigationModule(),                 # phase vuln : confirme les findings (anti-faux-positif)
        DefaultCredsHTTP(stealth=stealth),     # phase exploit (exemple / template)
        ExploitSSH(stealth=stealth),           # phase exploit (SSH)
        ExploitWeb(stealth=stealth),           # phase exploit (web)
        PostExploit(
            stealth=stealth,
            enabled=resolved_allow,
            dry_run=dry_run or resolved_mode == "audit",
            exploit_policy=policy,
            allow_data_access=allow_data_access,
            allow_service_shutdown=allow_service_shutdown,
            allow_web_shutdown=allow_web_shutdown,
        ),
        ReportModule(report_path, stealth_name=stealth.name),  # phase report
        # -> tes futurs modules (énum web, AD, exploits de lab...) viennent ici
    ]

    if resolved_mode == "audit":
        modules.append(AuditNotice())

    for module in modules:
        if getattr(module, "phase", None) == "exploit" or getattr(module, "phase", None) == "post":
            module.enabled = resolved_allow
            module.dry_run = dry_run or resolved_mode == "audit"
            module.exploit_policy = policy
            module.min_severity = exploit_min_severity
            if hasattr(module, "allow_data_access"):
                module.allow_data_access = allow_data_access
            if hasattr(module, "allow_service_shutdown"):
                module.allow_service_shutdown = allow_service_shutdown
            if hasattr(module, "allow_web_shutdown"):
                module.allow_web_shutdown = allow_web_shutdown

    return modules


BANNER = r"""
  ____  ____  ____  ____  _   _  ____  _____  ____   ___  ____  _  _
 |  _ \|  _ \|  _ \/ ___|| | | ||  _ \| ____|/ ___| / _ \/ ___|| || |
 | |_) | |_) | |_) \___ \| |_| || | | |  _|  \___ \| | | \___ \| || |
 |  __/|  _ <|  __/ ___) |  _  || |_| | |___  ___) | |_| |___) | || |
 |_|   |_| \_\_|   |_____|_| |_|_____|_____|_____|\___/ \___/|_____|_||_|
                 RED TEAM ORCHESTRATOR   MISSION ACTIVE
                 usage autorisé uniquement — périmètre contrôlé
"""


def print_showcase_briefing(args: argparse.Namespace) -> None:
    print("\n[+] Mission briefing")
    print(f"    mode          : {args.mode}")
    print(f"    stealth       : {args.stealth}")
    print(f"    exploit level : {args.exploit_min_severity}")
    print(f"    evidence      : {'required' if args.require_evidence else 'optional'}")
    print(f"    report        : {args.report}")
    print("    objective     : validate live attack paths inside the authorized lab scope\n")


def main() -> None:
    print(BANNER)
    p = argparse.ArgumentParser(description="Red Team Orchestrator (usage autorisé uniquement)")
    p.add_argument("--scope", required=True, help="Fichier YAML du périmètre autorisé")
    p.add_argument("--targets", nargs="*", default=[], help="Cibles (IP ou hôtes)")
    p.add_argument("--targets-file", help="Fichier texte, une cible par ligne")
    p.add_argument("--nvd-key", default=None, help="Clé API NVD (optionnelle, accélère le matching CVE)")
    p.add_argument("--report", default="rapport.md", help="Chemin du rapport de sortie")
    p.add_argument("--stealth", default="quiet", choices=["ghost", "quiet", "normal"],
                   help="Profil de furtivité : ghost (le plus discret, mode fantôme) | quiet | normal (rapide)")
    p.add_argument("--mode", choices=["audit", "validate", "exploit"], default="audit",
                   help="Mode d'exécution : audit (défaut prudent, aucun exploit), validate, exploit (lab autorisé uniquement).")
    p.add_argument("--demo", action="store_true",
                   help="Active la démonstration premium : mode exploit + autorisation explicite + briefing de mission.")
    p.add_argument("--auto", action="store_true",
                   help="Exécute une mission entièrement automatisée dans le périmètre autorisé : recon → enum → vuln → exploit contrôlé → rapport.")
    p.add_argument("--allow-exploit", action="store_true",
                   help="Autorise explicitement l'exécution des modules d'exploitation (PoC contrôlé).")
    p.add_argument("--allow-data-access", action="store_true",
                   help="Autorise explicitement les actions de post-exploitation sur les données sensibles d'un lab validé.")
    p.add_argument("--allow-service-stop", action="store_true",
                   help="Autorise explicitement un arrêt de service contrôlé dans le périmètre de test, après preuve explicite.")
    p.add_argument("--allow-web-disable", action="store_true",
                   help="Autorise explicitement l'arrêt ou la désactivation d'un service web dans le lab, après preuve explicite.")
    p.add_argument("--exploit-min-severity", choices=["low", "medium", "high", "critical"], default="low",
                   help="Seuil minimum de gravité requis avant qu'un PoC soit autorisé.")
    p.add_argument("--require-evidence", action=argparse.BooleanOptionalAction, default=False,
                   help="Exige au moins un élément de preuve (CVE, détail, preuve de reproduction) avant exploitation.")
    p.add_argument("--dry-run", action="store_true",
                   help="Vérifie les pré-conditions sans lancer les PoC d'exploitation.")
    p.add_argument("--verbose", action="store_true", help="Logs détaillés (horodatage + niveau)")
    p.add_argument("--log-file", default=None, help="Écrire aussi les logs dans ce fichier")
    args = p.parse_args()

    resolve_runtime_profile(args)

    setup_logging(args.verbose, args.log_file)
    log = logging.getLogger("rto")
    print_showcase_briefing(args)

    targets = list(args.targets)
    if args.targets_file:
        targets += [
            line.strip()
            for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    if not targets:
        p.error("Aucune cible fournie (--targets ou --targets-file).")

    scope = Scope.from_file(args.scope)
    log.info(f"[*] Périmètre chargé : {len(scope.hosts)} hôte(s) + {len(scope.networks)} réseau(x) autorisés.")
    log.info(f"[*] Profil de furtivité : {args.stealth}")
    log.info("[!] Rappel : n'utilise cet outil que sur des cibles explicitement autorisées.")
    effective_allow = args.mode != "audit" and (
        args.allow_exploit or args.mode == "exploit" or args.allow_data_access
        or args.allow_service_stop or args.allow_web_disable
    )
    if args.dry_run:
        log.warning("[!] Mode dry-run activé : validation des prérequis uniquement, sans exploitation réelle.")
    elif not effective_allow:
        log.warning("[!] Modules d'exploitation désactivés par défaut. Ajoute --allow-exploit, --allow-data-access, --allow-service-stop ou --allow-web-disable pour les activer.")
    else:
        log.warning("[!] Modules d'exploitation autorisés : exécution de PoC contrôlée uniquement dans le périmètre.")
    log.warning(
        "[!] Mode mission : %s | min=%s | preuve=%s | data=%s | service_stop=%s | web_stop=%s",
        args.mode,
        args.exploit_min_severity,
        "requise" if args.require_evidence else "non requise",
        args.allow_data_access,
        args.allow_service_stop,
        args.allow_web_disable,
    )

    engine = Engine(
        scope=scope,
        modules=build_modules(
            args.nvd_key,
            args.report,
            args.stealth,
            allow_exploit=effective_allow,
            dry_run=args.dry_run,
            exploit_min_severity=args.exploit_min_severity,
            require_evidence=args.require_evidence,
            mode=args.mode,
            allow_data_access=args.allow_data_access,
            allow_service_shutdown=args.allow_service_stop,
            allow_web_shutdown=args.allow_web_disable,
        ),
    )
    engine.run(targets)


if __name__ == "__main__":
    main()
