"""
report_pdf.py — Export PDF du rapport (via fpdf2).

Le PDF est généré DIRECTEMENT depuis les données structurées du Context
(pas en parsant le Markdown) : plus robuste, et mise en page maîtrisée.
C'est le livrable "à rendre / imprimer" pour la soutenance.

Dépendance : fpdf2  (pip install fpdf2). Si absente, le module le signale
proprement et on se rabat sur le HTML (imprimable en PDF depuis le navigateur).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core.attack import describe
from core.context import Context
from core.reporting import (
    CONF_LABEL, SEV_LABEL, SEV_ORDER, _authorization_details,
    _finding_report_fields, _risk_score,
)
from core.scope import Scope

SEV_RGB = {
    "critical": (127, 29, 29), "high": (185, 28, 28), "medium": (194, 65, 12),
    "low": (161, 98, 7), "info": (51, 65, 85),
}


def _mc(pdf, height: float, text: str) -> None:
    """multi_cell pleine largeur qui ramène toujours le curseur à la marge gauche."""
    pdf.multi_cell(0, height, text, new_x="LMARGIN", new_y="NEXT")


def _latin1(text: str) -> str:
    """fpdf2 (polices core) est en latin-1 : on remplace les caractères hors jeu."""
    repl = {"—": "-", "–": "-", "’": "'", "‘": "'", "“": '"', "”": '"',
            "→": "->", "•": "-", "🛠": "", "👻": "", "…": "..."}
    for k, v in repl.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")


def generate_pdf(ctx: Context, out_path: str | Path, stealth_name: str | None = None,
                 scope: Scope | None = None) -> Path | None:
    try:
        from fpdf import FPDF
    except ImportError:
        return None  # fpdf2 absent — l'appelant se rabattra sur le HTML

    out = Path(out_path)
    score, label = _risk_score(ctx)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Titre
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, _latin1("Rapport de mission - Red Team Orchestrator"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100)
    pdf.cell(0, 6, _latin1(f"Genere le {now}  |  Profil furtif : {stealth_name or 'n/a'}"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0)
    pdf.ln(4)

    # Résumé exécutif
    _h2(pdf, "Resume executif")
    pdf.set_font("Helvetica", "", 11)
    _mc(pdf, 6, _latin1(
        f"La mission a couvert {len(ctx.hosts)} hote(s) et identifie "
        f"{len(ctx.all_services())} service(s) expose(s), donnant lieu a "
        f"{len(ctx.findings)} finding(s). Score de risque global : {score}/100 ({label})."
    ))
    pdf.ln(2)

    _h2(pdf, "Autorisation et perimetre")
    pdf.set_font("Helvetica", "", 10)
    for detail in _authorization_details(ctx, scope):
        _mc(pdf, 5, _latin1("- " + detail))
    pdf.ln(2)

    # Surface d'attaque
    _h2(pdf, "Surface d'attaque")
    for host in ctx.hosts.values():
        pdf.set_font("Helvetica", "B", 11)
        name = host.address + (f" ({host.hostname})" if host.hostname else "")
        pdf.cell(0, 6, _latin1(name), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        if host.os_guess:
            pdf.cell(0, 5, _latin1(f"  OS suppose : {host.os_guess}"), new_x="LMARGIN", new_y="NEXT")
        for s in host.services:
            line = f"  {s.port}/{s.proto}  {s.name}  {s.product} {s.version}".rstrip()
            pdf.cell(0, 5, _latin1(line), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    # Findings
    _h2(pdf, "Vulnerabilites & findings")
    for f in sorted(ctx.findings, key=lambda x: SEV_ORDER.get(x.severity, 9)):
        title, detail, remediation = _finding_report_fields(f)
        r, g, b = SEV_RGB.get(f.severity, (51, 65, 85))
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(r, g, b)
        _mc(pdf, 6, _latin1(f"[{SEV_LABEL.get(f.severity, f.severity.upper())}] {title}"))
        pdf.set_text_color(0)
        pdf.set_font("Helvetica", "", 10)
        _mc(pdf, 5, _latin1(f"Hote : {f.host}  |  Confiance : {CONF_LABEL.get(f.confidence, f.confidence)}"))
        if detail:
            _mc(pdf, 5, _latin1(f"Detail : {detail}"))
        if f.evidence:
            _mc(pdf, 5, _latin1(f"Preuve : {f.evidence}"))
        if f.steps:
            _mc(pdf, 5, _latin1("Reproduction : " + " -> ".join(f.steps)))
        if f.attack_refs:
            _mc(pdf, 5, _latin1("MITRE ATT&CK : " + " ; ".join(describe(t) for t in f.attack_refs)))
        if remediation:
            pdf.set_font("Helvetica", "I", 10)
            pdf.set_text_color(5, 102, 102)
            _mc(pdf, 5, _latin1(f"Remediation : {remediation}"))
            pdf.set_text_color(0)
        pdf.ln(2)

    pdf.output(str(out))
    return out


def _h2(pdf, title: str) -> None:
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255)
    pdf.cell(0, 8, _latin1("  " + title), new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_text_color(0)
    pdf.ln(2)
