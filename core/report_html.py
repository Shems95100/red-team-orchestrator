"""
report_html.py — Rapport HTML auto-suffisant (CSS inline, aucune dépendance).

Rendu propre, lisible, imprimable en PDF depuis n'importe quel navigateur
(Ctrl+P). Reprend les mêmes sections que le rapport Markdown, avec des badges
de criticité colorés.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path

from core.attack import describe
from core.context import Context
from core.reporting import (
    CONF_LABEL, SEV_LABEL, SEV_ORDER, _authorization_details,
    _finding_report_fields, _risk_score,
)
from core.scope import Scope

SEV_COLOR = {
    "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#c2410c",
    "low": "#a16207", "info": "#334155",
}

CSS = """
:root{
  --bg:#0b1020; --bg2:#111827; --panel:#121b2d; --panel2:#162134; --line:#263244;
  --text:#e5edf9; --muted:#a5b4cf; --good:#22c55e; --warn:#f59e0b; --bad:#ef4444; --info:#60a5fa;
}
body{font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:1100px;margin:32px auto;padding:0 24px;background:radial-gradient(circle at top,#1a2335 0%,#0b1020 30%,#050b16 100%);color:var(--text);line-height:1.6}
body:before{content:"";position:fixed;top:0;left:0;right:0;height:8px;background:linear-gradient(90deg,#ef4444,#f97316,#facc15,#22c55e,#60a5fa,#a855f7)}
h1{margin:0 0 10px;font-size:2.2rem;border-bottom:2px solid rgba(96,165,250,.7);padding-bottom:10px;letter-spacing:.04em;text-transform:uppercase;color:#f3f7ff;text-shadow:0 0 18px rgba(96,165,250,.5)}
h2{margin-top:30px;padding-bottom:8px;margin-bottom:12px;border-bottom:1px solid rgba(96,165,250,.4);color:#f8fbff;letter-spacing:.06em;text-transform:uppercase}
h3{margin-top:18px;color:#dfe9ff}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;color:#fff;font-size:12px;font-weight:700;letter-spacing:.3px;box-shadow:0 0 15px rgba(239,68,68,.35)}
.finding{border:1px solid rgba(96,165,250,.35);border-left-width:6px;border-radius:12px;padding:14px 16px;margin:14px 0;background:linear-gradient(180deg,rgba(15,23,42,.9),rgba(10,17,29,.98));box-shadow:0 0 25px rgba(59,130,246,.08),0 8px 30px rgba(0,0,0,.22)}
.kpi{display:inline-block;background:linear-gradient(135deg,#111827,#1e293b);color:#fff;border:1px solid rgba(96,165,250,.5);border-radius:12px;padding:14px 18px;margin:6px 8px 6px 0;text-align:center;min-width:150px;box-shadow:0 0 22px rgba(96,165,250,.12),0 12px 20px rgba(0,0,0,.18)}
.kpi .n{font-size:28px;font-weight:800;display:block;color:#f8fbff}
.summary-box{background:linear-gradient(135deg,rgba(17,24,39,.95),rgba(30,41,59,.9));border:1px solid rgba(96,165,250,.35);border-radius:12px;padding:16px 18px;margin:14px 0;color:var(--text);box-shadow:0 0 18px rgba(96,165,250,.08),0 10px 25px rgba(0,0,0,.18)}
.summary-box strong{color:#f8fbff}
.rem{background:rgba(34,197,94,.08);border-left:4px solid var(--good);padding:10px 12px;margin-top:10px;border-radius:6px;color:#dfffe9}
.att{color:var(--muted);font-size:13px}
code{background:#0f172a;border:1px solid rgba(96,165,250,.3);padding:2px 6px;border-radius:6px;font-size:13px;color:#dbeafe}
table{border-collapse:collapse;width:100%;background:rgba(15,23,42,.7);border:1px solid rgba(96,165,250,.25);border-radius:8px;overflow:hidden}td,th{border:1px solid rgba(96,165,250,.2);padding:8px 10px;text-align:left;color:var(--text)}
.muted{color:var(--muted);font-size:13px}
pre{background:linear-gradient(180deg,#0f172a,#0b1020);color:#d8e6ff;padding:14px;border-radius:12px;overflow-x:auto;font-size:12px;border:1px solid rgba(96,165,250,.2);box-shadow:inset 0 0 12px rgba(96,165,250,.05)}
"""


def generate_html(ctx: Context, out_path: str | Path, stealth_name: str | None = None,
                  scope: Scope | None = None) -> Path:
    out = Path(out_path)
    score, label = _risk_score(ctx)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts: dict[str, int] = {}
    for f in ctx.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    h: list[str] = []
    h.append(f"<!doctype html><html lang='fr'><head><meta charset='utf-8'>")
    h.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    h.append(f"<title>Rapport Red Team</title><style>{CSS}</style></head><body>")
    h.append("<h1>Rapport de mission — Red Team Orchestrator</h1>")
    h.append(f"<p class='muted'>Généré le {now} · Profil furtif : <b>{escape(stealth_name or 'n/a')}</b> · Mission : <b>exploitation autorisée</b></p>")

    h.append("<h2>Autorisation et périmètre</h2><div class='summary-box'>")
    for detail in _authorization_details(ctx, scope):
        h.append(f"<p>{escape(detail)}</p>")
    h.append("</div>")

    h.append("<div>")
    h.append(f"<div class='kpi'><span class='n'>{len(ctx.hosts)}</span>hôtes</div>")
    h.append(f"<div class='kpi'><span class='n'>{len(ctx.all_services())}</span>services</div>")
    h.append(f"<div class='kpi'><span class='n'>{len(ctx.findings)}</span>findings</div>")
    h.append(f"<div class='kpi'><span class='n'>{score}/100</span>RISQUE ({label})</div>")
    h.append("</div>")

    h.append("<div class='summary-box'>")
    h.append("<strong>Threat assessment :</strong> mission cyber tactique menée au sein du périmètre autorisé, avec validation des chemins d'attaque et documentation des risques critiques. ")
    h.append("<br><strong>Impact prioritaire :</strong> surface exposée active ; les chemins d'exploitation doivent être corrigés selon la criticité. ")
    h.append("<br><strong>Évaluation finale :</strong> " + escape(label) + " — niveau de risque opérationnel élevé et action corrective immédiate recommandée.")
    h.append("</div>")

    h.append("<h2>Briefing exécutif</h2>")
    h.append("<div class='summary-box'>")
    h.append("<strong>Objectif de la mission :</strong> valider les chemins d'attaque exploitable à l'intérieur du périmètre autorisé et documenter les vulnérabilités avec preuve.")
    h.append("<br><strong>Posture actuelle :</strong> la surface exposée est active, les chemins critiques ont été identifiés et la remédiation doit être priorisée selon la criticité.")
    h.append("<br><strong>Évaluation globale :</strong> " + escape(label) + " — le niveau de risque justifie une action corrective immédiate.")
    h.append("</div>")

    # Surface d'attaque
    h.append("<h2>Surface d'attaque</h2>")
    for host in ctx.hosts.values():
        name = escape(host.address) + (f" ({escape(host.hostname)})" if host.hostname else "")
        h.append(f"<h3>{name}</h3>")
        if host.os_guess:
            h.append(f"<p class='muted'>OS supposé : {escape(host.os_guess)}</p>")
        if host.services:
            h.append("<table><tr><th>Port</th><th>Service</th><th>Produit</th><th>Version</th></tr>")
            for s in host.services:
                h.append(f"<tr><td>{s.port}/{escape(s.proto)}</td><td>{escape(s.name)}</td>"
                         f"<td>{escape(s.product)}</td><td>{escape(s.version)}</td></tr>")
            h.append("</table>")
        else:
            h.append("<p class='muted'>Aucun service ouvert détecté.</p>")

    # Findings
    h.append("<h2>Vulnérabilités &amp; findings</h2>")
    for f in sorted(ctx.findings, key=lambda x: SEV_ORDER.get(x.severity, 9)):
        title, detail, remediation = _finding_report_fields(f)
        color = SEV_COLOR.get(f.severity, "#334155")
        h.append(f"<div class='finding' style='border-left-color:{color}'>")
        h.append(f"<span class='badge' style='background:{color}'>{SEV_LABEL.get(f.severity, f.severity.upper())}</span> ")
        h.append(f"<b>{escape(title)}</b>")
        h.append(f"<div class='muted'>Hôte : <code>{escape(f.host)}</code> · "
                 f"Confiance : {escape(CONF_LABEL.get(f.confidence, f.confidence))}</div>")
        if detail:
            h.append(f"<div>{escape(detail)}</div>")
        if f.evidence:
            h.append(f"<div class='muted'>Preuve : {escape(f.evidence)}</div>")
        if f.steps:
            h.append("<div class='muted'>Reproduction : " +
                     escape(" → ".join(f.steps)) + "</div>")
        if f.attack_refs:
            h.append("<div class='att'>MITRE ATT&amp;CK : " +
                     " ; ".join(escape(describe(t)) for t in f.attack_refs) + "</div>")
        if remediation:
            h.append(f"<div class='rem'>🛠 Remédiation : {escape(remediation)}</div>")
        h.append("</div>")

    # Timeline
    h.append("<h2>Déroulé de la mission</h2><pre>")
    for e in ctx.timeline:
        h.append(escape(f"{e['ts']}  [{e['module']}] {e['message']}"))
    h.append("</pre>")

    h.append("</body></html>")
    out.write_text("\n".join(h), encoding="utf-8")
    return out
