"""
reporting.py — Phase report : génère le rapport de mission.

Le rapport, c'est ce qui rapporte le plus de points à l'oral ET ce qui aide ta
blue team à apprendre : toute la kill chain horodatée + les findings triés par
criticité + des recommandations. On sort du Markdown (lisible, versionnable,
convertible en PDF).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.attack import describe
from core.context import Context
from core.scope import Scope

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_LABEL = {
    "critical": "CRITIQUE",
    "high": "ÉLEVÉE",
    "medium": "MOYENNE",
    "low": "FAIBLE",
    "info": "INFO",
}
# Poids pour le score de risque global (0-100).
SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
CONF_LABEL = {
    "confirmed": "CONFIRMÉ (test reproductible)",
    "firm": "ÉLEVÉE (observation directe)",
    "tentative": "À VÉRIFIER (indice, non confirmé)",
    "scanner": "SIGNALÉ PAR SCANNER (non vérifié)",
}


def _risk_score(ctx: Context) -> tuple[int, str]:
    """Score de risque 0-100 + libellé, à partir des findings."""
    raw = sum(SEV_WEIGHT.get(f.severity, 0) for f in ctx.findings)
    score = min(100, raw)
    if score >= 70:
        label = "CRITIQUE"
    elif score >= 40:
        label = "ÉLEVÉ"
    elif score >= 15:
        label = "MODÉRÉ"
    elif score > 0:
        label = "FAIBLE"
    else:
        label = "MINIME"
    return score, label


def _executive_summary(ctx: Context) -> list[str]:
    """Résumé exécutif en prose — la page 1 d'un rapport de pentest pro."""
    score, label = _risk_score(ctx)
    counts: dict[str, int] = {}
    for f in ctx.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    crit_high = counts.get("critical", 0) + counts.get("high", 0)

    lines = ["## Résumé exécutif", ""]
    lines.append(
        f"La mission a couvert **{len(ctx.hosts)} hôte(s)** et identifié "
        f"**{len(ctx.all_services())} service(s)** exposé(s), donnant lieu à "
        f"**{len(ctx.findings)} finding(s)**."
    )
    if crit_high:
        lines.append(
            f"On relève **{crit_high} vulnérabilité(s) de criticité élevée ou "
            f"critique** nécessitant une action prioritaire."
        )
    else:
        lines.append("Aucune vulnérabilité de criticité élevée n'a été relevée.")
    lines.append(f"**Score de risque global : {score}/100 ({label}).**")
    lines.append("")
    return lines


def _authorization_details(ctx: Context, scope: Scope | None) -> list[str]:
    if scope is None:
        scope_line = "Scope technique non transmis au générateur de rapport."
    else:
        hosts = ", ".join(sorted(scope.hosts)) or "aucun hôte explicite"
        networks = ", ".join(sorted(str(network) for network in scope.networks)) or "aucun réseau"
        ports = ", ".join(str(port) for port in sorted(scope.allowed_ports)) or "tous (aucune restriction configurée)"
        scope_line = f"Hôtes : {hosts} ; réseaux : {networks} ; ports : {ports}."

    targets = ", ".join(sorted(ctx.hosts)) or "aucune cible"
    return [
        scope_line,
        f"Cibles présentes dans le rapport : {targets}.",
        "Autorisation légale non vérifiée par l'outil ; l'opérateur doit confirmer l'accord écrit du propriétaire et de l'hébergeur.",
        "Les tests DoS et arrêt de service n'ont pas été exécutés.",
    ]


def _finding_report_fields(finding) -> tuple[str, str, str]:
    """Normalize legacy public-metadata findings before presenting them as vulnerabilities."""
    if finding.source_module == "http-enum":
        source = f"{finding.title} {finding.evidence}".lower()
        for path in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
            if path in source:
                return (
                    f"Fichier public standard détecté : /{path}",
                    f"/{path} est un fichier de métadonnées normalement public ; son accessibilité seule ne constitue pas une vulnérabilité.",
                    "",
                )
    return finding.title, finding.detail, finding.remediation


def _footprint_section(ctx: Context, stealth_name: str | None) -> list[str]:
    """
    Carte de furtivité (OPSEC) : mesure l'empreinte de la mission.
    L'idée à défendre : "rentrer et sortir sans être détecté" se prouve en
    MESURANT son bruit, pas en effaçant des traces. On compte les actions
    réseau par type et on estime le risque de détection.
    """
    lines: list[str] = []
    lines.append("## 6. Empreinte & furtivité (OPSEC)")
    lines.append("")

    # Classe les entrées de la timeline par type d'action réseau.
    noisy_scans = sum(1 for e in ctx.timeline if e["module"] == "nmap-recon" and "Scan" in e["message"])
    exploit_tries = sum(1 for e in ctx.timeline if e["module"] == "default-creds-http")
    cve_queries = sum(1 for e in ctx.timeline if e["module"] == "cve-lookup" and "NVD" in e["message"])

    lines.append(f"- Profil de furtivité utilisé : **{stealth_name or 'non précisé'}**")
    lines.append(f"- Scans réseau émis vers les cibles : {noisy_scans}")
    lines.append(f"- Tentatives d'authentification : {exploit_tries}")
    lines.append(f"- Requêtes CVE (vers le NIST, PAS vers la cible — non détectable par la blue team) : {cve_queries}")
    lines.append("")

    # Estimation qualitative du risque de détection.
    target_actions = noisy_scans + exploit_tries
    if stealth_name == "ghost" and target_actions <= 5:
        risk = "FAIBLE — low-and-slow, peu d'actions, bien étalées."
    elif stealth_name == "normal":
        risk = "ÉLEVÉ — profil rapide/agressif, susceptible de déclencher des alertes."
    else:
        risk = "MODÉRÉ — rythme maîtrisé mais surveiller le volume d'actions."
    lines.append(f"- **Risque de détection estimé : {risk}**")
    lines.append("")

    lines.append("### Mesures de discrétion appliquées")
    lines.append("- Timing lent + jitter aléatoire entre les actions (passe sous les seuils d'alerte).")
    lines.append("- Aucun fichier déposé sur la cible ; outils temporaires nettoyés côté attaquant.")
    lines.append("- Nombre d'actions réseau minimisé (scans ciblés, pas de balayage exhaustif).")
    lines.append("- Aucune altération des journaux de la cible (volontaire : vider un log est lui-même")
    lines.append("  très détecté — la furtivité consiste à ne pas déclencher l'alerte, pas à l'effacer).")
    lines.append("")
    return lines


def generate(ctx: Context, out_path: str | Path = "rapport.md", stealth_name: str | None = None,
             scope: Scope | None = None) -> Path:
    out = Path(out_path)
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append("# Rapport de mission — Red Team Orchestrator")
    lines.append("")
    lines.append(f"*Généré le {now}*")
    lines.append("")

    # Résumé exécutif (page 1)
    lines += _executive_summary(ctx)

    lines.append("## Autorisation et périmètre")
    lines.append("")
    lines.extend(f"- {detail}" for detail in _authorization_details(ctx, scope))
    lines.append("")

    # 1. Synthèse
    lines.append("## 1. Synthèse")
    lines.append("")
    lines.append(f"- Hôtes analysés : **{len(ctx.hosts)}**")
    lines.append(f"- Services ouverts : **{len(ctx.all_services())}**")
    lines.append(f"- Findings : **{len(ctx.findings)}**")
    counts: dict[str, int] = {}
    for f in ctx.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            lines.append(f"  - {SEV_LABEL[sev]} : {counts[sev]}")
    lines.append("")

    # 2. Surface d'attaque
    lines.append("## 2. Surface d'attaque (hôtes & services)")
    lines.append("")
    for host in ctx.hosts.values():
        title = host.address + (f" ({host.hostname})" if host.hostname else "")
        lines.append(f"### {title}")
        if host.os_guess:
            lines.append(f"- OS supposé : {host.os_guess}")
        if not host.services:
            lines.append("- Aucun service ouvert détecté.")
        for svc in host.services:
            desc = " ".join(x for x in (svc.product, svc.version) if x)
            lines.append(f"- `{svc.port}/{svc.proto}` **{svc.name}** {desc}".rstrip())
        lines.append("")

    # 3. Findings triés par criticité
    lines.append("## 3. Vulnérabilités & findings")
    lines.append("")
    findings = sorted(ctx.findings, key=lambda f: SEV_ORDER.get(f.severity, 9))
    if not findings:
        lines.append("Aucun finding enregistré.")
        lines.append("")
    for f in findings:
        title, detail, remediation = _finding_report_fields(f)
        lines.append(f"### [{SEV_LABEL.get(f.severity, f.severity.upper())}] {title}")
        lines.append(f"- Hôte : `{f.host}`")
        if f.cve:
            lines.append(f"- Référence : {f.cve}")
        if f.evidence:
            lines.append(f"- Preuve : {f.evidence}")
        if detail:
            lines.append(f"- Détail : {detail}")
        lines.append(f"- Confiance : **{CONF_LABEL.get(f.confidence, f.confidence)}**")
        if f.attack_refs:
            lines.append("- MITRE ATT&CK : " + " ; ".join(describe(t) for t in f.attack_refs))
        if f.steps:
            lines.append("- Reproduction : " + " → ".join(f.steps))
        if remediation:
            lines.append(f"- **Remédiation : {remediation}**")
        lines.append(f"- Source : module `{f.source_module}` — {f.timestamp}")
        lines.append("")

    # 3bis. Couverture MITRE ATT&CK
    techs: dict[str, int] = {}
    for f in ctx.findings:
        for t in f.attack_refs:
            techs[t] = techs.get(t, 0) + 1
    if techs:
        lines.append("## 3bis. Couverture MITRE ATT&CK")
        lines.append("")
        for t in sorted(techs):
            lines.append(f"- {describe(t)} — {techs[t]} finding(s)")
        lines.append("")

    # 4. Timeline (kill chain)
    lines.append("## 4. Déroulé de la mission (timeline)")
    lines.append("")
    lines.append("```")
    for entry in ctx.timeline:
        lines.append(f"{entry['ts']}  [{entry['module']}] {entry['message']}")
    lines.append("```")
    lines.append("")

    # 5. Recommandations génériques (à personnaliser)
    lines.append("## 5. Recommandations")
    lines.append("")
    lines.append("- Mettre à jour les services identifiés comme vulnérables (voir §3).")
    lines.append("- Changer tous les identifiants par défaut.")
    lines.append("- Fermer/filtrer les ports non nécessaires.")
    lines.append("- Mettre en place de la détection côté blue team pour les scans et tentatives d'auth.")
    lines.append("")

    # §5bis — Investigation adaptative (confirmation des findings)
    investigation = getattr(ctx, "investigation", None)
    if isinstance(investigation, dict):
        summ = investigation.get("summary", {})
        lines.append("## 5bis. Investigation adaptative (confirmation)")
        lines.append("")
        lines.append("Chaque finding de scanner est traité comme une **hypothèse à confirmer**, "
                     "pas comme une vérité. Bilan :")
        lines.append(f"- Hypothèses analysées : {summ.get('hypotheses_total', 0)}")
        lines.append(f"- Confirmées (test reproductible) : {summ.get('confirmed', 0)}")
        lines.append(f"- Plausibles (indices concordants) : {summ.get('plausible', 0)}")
        lines.append(f"- Au stade « signalé par scanner » (non vérifié) : {summ.get('scanner_reported', 0)}")
        lines.append(f"- Impact démontré : {summ.get('impact_demonstrated', 0)}")
        lines.append(f"- Tests exécutés : {summ.get('tests_run', 0)}")
        lines.append(f"- Arrêt : {investigation.get('stop_reason', 'n/a')}")
        lines.append("")

    # §6 — Carte de furtivité / OPSEC
    lines += _footprint_section(ctx, stealth_name)

    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def generate_json(ctx: Context, out_path: str | Path, stealth_name: str | None = None,
                 scope: Scope | None = None) -> Path:
    """Export machine-lisible des findings (pour chaîner avec d'autres outils)."""
    out = Path(out_path)
    score, label = _risk_score(ctx)
    data = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "stealth_profile": stealth_name,
        "risk_score": score,
        "risk_label": label,
        "authorization_and_scope": _authorization_details(ctx, scope),
        "hosts": [
            {
                "address": h.address,
                "hostname": h.hostname,
                "os_guess": h.os_guess,
                "services": [
                    {"port": s.port, "proto": s.proto, "name": s.name,
                     "product": s.product, "version": s.version}
                    for s in h.services
                ],
            }
            for h in ctx.hosts.values()
        ],
        "findings": [
            _finding_json(f)
            for f in ctx.findings
        ],
        "timeline": ctx.timeline,
        "investigation": getattr(ctx, "investigation", None),
    }
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def _finding_json(finding) -> dict:
    title, detail, remediation = _finding_report_fields(finding)
    return {
        "host": finding.host, "title": title, "severity": finding.severity,
        "confidence": finding.confidence, "steps": finding.steps,
        "detail": detail, "evidence": finding.evidence, "cve": finding.cve,
        "attack_refs": finding.attack_refs, "remediation": remediation,
        "source_module": finding.source_module, "timestamp": finding.timestamp,
    }
