"""
check_default_creds.py — EXEMPLE de module de phase "exploit".

Ce fichier a deux buts :
  1. Faire une vérif réelle et utile en lab : beaucoup de services exposent une
     authentification HTTP Basic avec des identifiants par défaut (admin/admin,
     etc.). C'est un classique du pentest et un vrai point à trouver.
  2. Te servir de TEMPLATE. Tu copies ce fichier pour écrire tes propres modules
     d'exploitation adaptés à ce que tu découvres dans ton lab autorisé
     (une injection sur une app volontairement vulnérable, un creds par défaut
     sur un service précis, etc.). Tu gardes la même structure :
        - hériter de Module, phase = "exploit"
        - should_run() : ne se déclenche que si la cible pertinente existe
        - run() : appeler guard(scope, cible) AVANT toute requête, puis agir

Volontairement limité : liste minuscule, 1 essai par identifiant, aucun flood.
Un module de pentest sérieux teste quelques defaults connus — il ne fait pas du
brute-force massif (bruyant, destructeur, et hors-sujet pour la note).
"""

from __future__ import annotations

import base64
import urllib.request

from core.context import Context, Finding
from core.exploit_policy import ExploitPolicy
from core.scope import Scope, guard
from core.stealth import StealthProfile, get_profile
from modules.base import Module

# Petite liste de démonstration. À adapter au matériel/app de ton lab.
DEFAULT_PAIRS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("tomcat", "tomcat"),
]


class DefaultCredsHTTP(Module):
    name = "default-creds-http"
    phase = "exploit"
    attack_refs = ["T1110.001", "T1078"]  # Password Guessing + Valid Accounts
    min_severity = "medium"

    def __init__(self, stealth: StealthProfile | None = None, enabled: bool = False, dry_run: bool = False,
                 exploit_policy: ExploitPolicy | None = None):
        self.stealth = stealth or get_profile("quiet")
        self.enabled = enabled
        self.dry_run = dry_run
        self.exploit_policy = exploit_policy

    def should_run(self, ctx: Context) -> bool:
        if not self.enabled or self.dry_run:
            return False
        has_web = any(
            svc.name in ("http", "https", "http-proxy") or svc.port in (80, 443, 8080, 8443)
            for svc in ctx.all_services()
        )
        if not has_web:
            return False
        return self.has_service_ready_for_exploit(
            ctx,
            service_names=("http", "https", "http-proxy"),
            ports=(80, 443, 8080, 8443),
            keywords=["http", "auth", "default", "credential", "login", "cve"],
        )

    def _candidate_login_paths(self, base: str) -> list[str]:
        paths = ["", "/", "/login", "/admin", "/admin/login", "/auth", "/index.php", "/login.php", "/admin.php"]
        return [base.rstrip("/") + suffix for suffix in paths]

    def run(self, ctx: Context, scope: Scope) -> None:
        for svc in ctx.all_services():
            is_web = svc.name in ("http", "https", "http-proxy") or svc.port in (80, 443, 8080, 8443)
            if not is_web:
                continue

            guard(scope, svc.host)

            scheme = "https" if (svc.name == "https" or svc.port in (443, 8443)) else "http"
            base = f"{scheme}://{svc.host}:{svc.port}/"
            candidate_paths = self._candidate_login_paths(base)

            auth_target = None
            for candidate in candidate_paths:
                if self._basic_auth_required(candidate):
                    auth_target = candidate
                    break
            if not auth_target:
                ctx.log(self.name, f"Pas d'auth HTTP Basic sur {base} — rien à tester (évite un faux positif).")
                continue

            for user, pwd in DEFAULT_PAIRS:
                self.stealth.sleep()
                if self._creds_work(auth_target, user, pwd):
                    ctx.add_finding(
                        Finding(
                            host=svc.host,
                            title=f"Identifiants par défaut acceptés ({user}:{pwd})",
                            severity="critical",
                            confidence="confirmed",
                            detail=f"L'authentification HTTP Basic sur {auth_target} exige des identifiants "
                                   f"et accepte un couple par défaut. La voie d'accès est validée dans le périmètre autorisé.",
                            evidence=f"{auth_target} -> {user}:{pwd} | http-basic-auth challenge observed",
                            source_module=self.name,
                            attack_refs=["T1078"],
                            remediation="Changer immédiatement les identifiants par défaut ; "
                                        "imposer une politique de mots de passe forts et le MFA si possible.",
                            steps=[
                                "Confirmer le point d'entrée HTTP Basic autorisé.",
                                "Valider le couple par défaut sur la cible lab.",
                                "Documenter le PoC et verrouiller les accès après la mission.",
                            ],
                        )
                    )
                    break

    def _basic_auth_required(self, url: str) -> bool:
        """
        True seulement si l'URL EXIGE une auth HTTP Basic : une requête SANS
        identifiants doit renvoyer 401 avec un en-tête WWW-Authenticate: Basic.
        C'est le garde-fou anti-faux-positif.
        """
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return False  # 200 sans auth = aucune auth exigée
        except urllib.error.HTTPError as e:
            if e.code == 401:
                www = (e.headers.get("WWW-Authenticate", "") or "").lower()
                return "basic" in www
            return False
        except Exception:  # noqa: BLE001
            return False

    def _creds_work(self, url: str, user: str, pwd: str) -> bool:
        """True si CES identifiants débloquent la ressource protégée (200)."""
        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except urllib.error.HTTPError:
            return False  # 401/403 = identifiants refusés
        except Exception:  # noqa: BLE001
            return False
