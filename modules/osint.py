"""
osint.py — Phase recon : collecte OSINT passive (orienté CTF / reconnaissance).

OSINT = Open Source INTelligence : rassembler l'information publique sur une
cible, sans l'attaquer. Pour un CTF, ça aide à trouver des sous-domaines, des
e-mails, des métadonnées exposées, des enregistrements DNS — autant de points
d'entrée.

Volontairement PASSIF et scope-guardé : résolution DNS, DNS inverse, et
extraction d'e-mails / liens / métadonnées depuis les pages déjà dans le
périmètre. Aucune énumération agressive de sous-domaines par force brute.
"""

from __future__ import annotations

import re
import socket
import urllib.error
import urllib.request

from core.context import Context, Finding
from core.scope import Scope, guard, make_scoped_opener
from modules.base import Module

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Métadonnées / secrets souvent laissés traîner dans le HTML ou le JS.
SECRET_HINT_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|aws_access|BEGIN [A-Z ]*PRIVATE KEY)"
)


class OsintRecon(Module):
    name = "osint"
    phase = "recon"
    attack_refs = ["T1591", "T1589", "T1596"]

    def should_run(self, ctx: Context) -> bool:
        return bool(ctx.hosts)

    def run(self, ctx: Context, scope: Scope) -> None:
        for address in list(ctx.hosts.keys()):
            guard(scope, address)
            self._dns(ctx, address)

        # Récupère les e-mails / secrets exposés sur les services web du périmètre.
        for svc in ctx.all_services():
            is_web = svc.name in ("http", "https", "http-proxy") or svc.port in (80, 443, 8080, 8443)
            if not is_web:
                continue
            guard(scope, svc.host, port=svc.port)
            scheme = "https" if (svc.name == "https" or svc.port in (443, 8443)) else "http"
            self._harvest(ctx, svc.host, f"{scheme}://{svc.host}:{svc.port}/", scope)

    def _dns(self, ctx: Context, address: str) -> None:
        # Résolution directe
        try:
            ips = sorted({info[4][0] for info in socket.getaddrinfo(address, None)})
        except Exception:  # noqa: BLE001
            ips = []
        if ips:
            ctx.add_finding(Finding(
                host=address, title="Résolution DNS",
                severity="info", confidence="firm",
                detail=f"{address} -> {', '.join(ips)}",
                evidence="DNS A/AAAA", source_module=self.name, attack_refs=["T1596"],
                steps=[f"nslookup {address}"],
            ))
        # DNS inverse (PTR) — révèle parfois un nom d'hôte parlant.
        for ip in ips:
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                if ptr and ptr.lower() != address.lower():
                    ctx.add_finding(Finding(
                        host=address, title=f"DNS inverse : {ip} -> {ptr}",
                        severity="info", confidence="firm",
                        detail="Le PTR peut révéler un nom d'hôte interne ou un indice.",
                        evidence=f"PTR {ip}", source_module=self.name,
                        steps=[f"nslookup {ip}"],
                    ))
            except Exception:  # noqa: BLE001
                pass

    def _harvest(self, ctx: Context, host: str, url: str, scope: Scope) -> None:
        body = self._get(url, scope)
        if not body:
            return
        emails = sorted(set(EMAIL_RE.findall(body)))
        if emails:
            ctx.add_finding(Finding(
                host=host, title=f"{len(emails)} e-mail(s) exposé(s) dans la page",
                severity="low", confidence="firm",
                detail="E-mails : " + ", ".join(emails[:10]),
                evidence=url, source_module=self.name, attack_refs=["T1589"],
                steps=[f"curl -s {url}", "Extraire les adresses e-mail (utiles pour du spray/OSINT)."],
            ))
        if SECRET_HINT_RE.search(body):
            hint = SECRET_HINT_RE.search(body).group(0)
            ctx.add_finding(Finding(
                host=host, title="Indice de secret exposé dans le contenu web",
                severity="medium", confidence="tentative",
                detail=f"Motif repéré : {hint} — à vérifier manuellement (clé/API/token ?).",
                evidence=url, source_module=self.name,
                steps=[f"curl -s {url}", "Chercher les clés/API/secrets dans le HTML et le JS liés."],
            ))

    def _get(self, url: str, scope: Scope):
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        scope.authorize_url(url)
        opener = make_scoped_opener(scope)
        try:
            with opener.open(req, timeout=10) as resp:
                return resp.read(200000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.read(200000).decode("utf-8", "replace") if e.fp else ""
        except Exception:  # noqa: BLE001
            return ""
