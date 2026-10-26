"""
cve_lookup.py — Phase vuln : matching des versions détectées avec des CVE À JOUR.

C'est la bonne réponse au besoin "connaître les failles récentes" : on ne stocke
PAS une base d'exploits en dur (impossible à maintenir et périmée en une semaine).
On interroge l'API publique NVD du NIST au moment du scan avec le produit + la
version détectés, et on récupère les CVE connues, triées par score CVSS.

API NVD 2.0 : https://services.nvd.nist.gov/rest/json/cves/2.0
Sans clé API : ~5 requêtes / 30s. Avec clé (gratuite) : bien plus.
On met donc un petit délai entre les requêtes pour rester poli.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

from core.context import Context, Finding, Service
from core.scope import Scope
from modules.base import Module

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


class CveLookup(Module):
    name = "cve-lookup"
    phase = "vuln"
    attack_refs = ["T1595.002"]  # Vulnerability Scanning

    def __init__(self, api_key: str | None = None, max_per_service: int = 5, delay: float = 6.0):
        self.api_key = api_key
        self.max_per_service = max_per_service
        self.delay = delay  # secondes entre requêtes (respect du rate-limit NVD)

    def should_run(self, ctx: Context) -> bool:
        # On ne tourne que si la recon a trouvé au moins un service versionné.
        return any(s.product and s.version for s in ctx.all_services())

    def run(self, ctx: Context, scope: Scope) -> None:
        seen: set[str] = set()
        for svc in ctx.all_services():
            if not (svc.product and svc.version):
                continue
            key = f"{svc.product} {svc.version}".lower()
            if key in seen:
                continue
            seen.add(key)
            self._lookup(ctx, svc)
            time.sleep(self.delay)

    def _lookup(self, ctx: Context, svc: Service) -> None:
        query = f"{svc.product} {svc.version}".strip()
        params = {"keywordSearch": query, "resultsPerPage": 20}
        url = f"{NVD_URL}?{urllib.parse.urlencode(params)}"
        headers = {"User-Agent": "redteam-orchestrator/edu"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        ctx.log(self.name, f"NVD : recherche CVE pour '{query}'")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            ctx.log(self.name, f"Échec requête NVD pour '{query}' : {e!r}")
            return

        vulns = data.get("vulnerabilities", [])
        scored = []
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            score = _extract_cvss(cve)
            desc = _extract_desc(cve)
            scored.append((score, cve_id, desc))

        # Les plus graves d'abord
        scored.sort(key=lambda x: x[0], reverse=True)
        for score, cve_id, desc in scored[: self.max_per_service]:
            ctx.add_finding(
                Finding(
                    host=svc.host,
                    title=f"{cve_id} — {svc.product} {svc.version} (CVSS {score})",
                    severity=_cvss_severity(score),
                    detail=f"{desc[:280]} {_impact_summary(cve)}".strip(),
                    evidence=f"Service {svc.name} sur {svc.host}:{svc.port}",
                    source_module=self.name,
                    cve=cve_id,
                    # Un match NVD par mot-clé est une PISTE, pas une preuve d'exploitabilité.
                    confidence="scanner",
                    attack_refs=["T1190"],  # Exploit Public-Facing Application
                    remediation=f"Mettre à jour {svc.product} vers une version non affectée par {cve_id} "
                                f"et appliquer les correctifs du fournisseur.",
                    steps=[f"Vérifier la version exacte de {svc.product} {svc.version}",
                           f"Confirmer l'applicabilité de {cve_id} à cette version/configuration"],
                )
            )


def _extract_cvss(cve: dict) -> float:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            try:
                return float(arr[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
    return 0.0


def _extract_desc(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _impact_summary(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    cvss_data = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            break
    if not cvss_data:
        return "Impact théorique CVSS (non vérifié) : métriques CIA indisponibles."

    labels = {"HIGH": "élevée", "COMPLETE": "totale", "LOW": "limitée", "PARTIAL": "partielle", "NONE": "nulle"}
    impacts = []
    for key, label in (
        ("confidentialityImpact", "confidentialité"),
        ("integrityImpact", "intégrité"),
        ("availabilityImpact", "disponibilité"),
    ):
        raw = str(cvss_data.get(key, "")).upper()
        impacts.append(f"{label}: {labels.get(raw, 'non précisée')}")
    return "Impact théorique CVSS (non vérifié) : " + ", ".join(impacts) + "."
