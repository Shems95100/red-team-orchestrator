"""
report_module.py — Branche le reporting dans le système de phases.

Émet plusieurs formats :
  - Markdown (rapport.md)   : lisible, versionnable
  - JSON (rapport.json)     : machine-lisible, pour chaîner avec d'autres outils
  - HTML (rapport.html)     : stylé, imprimable en PDF depuis le navigateur
  - PDF (rapport.pdf)       : livrable à rendre (si fpdf2 installé)
"""

from __future__ import annotations

from pathlib import Path

from core import reporting
from core.context import Context
from core.report_html import generate_html
from core.report_pdf import generate_pdf
from core.scope import Scope
from modules.base import Module


class ReportModule(Module):
    name = "report"
    phase = "report"

    def __init__(self, out_path: str = "rapport.md", stealth_name: str | None = None):
        self.out_path = out_path
        self.stealth_name = stealth_name

    def run(self, ctx: Context, scope: Scope) -> None:
        stem = str(Path(self.out_path).with_suffix(""))

        md = reporting.generate(ctx, stem + ".md", stealth_name=self.stealth_name, scope=scope)
        ctx.log(self.name, f"Rapport Markdown : {md}")

        reporting.generate_json(ctx, stem + ".json", stealth_name=self.stealth_name, scope=scope)
        ctx.log(self.name, f"Export JSON : {stem}.json")

        generate_html(ctx, stem + ".html", stealth_name=self.stealth_name, scope=scope)
        ctx.log(self.name, f"Rapport HTML : {stem}.html")

        pdf = generate_pdf(ctx, stem + ".pdf", stealth_name=self.stealth_name, scope=scope)
        if pdf:
            ctx.log(self.name, f"Rapport PDF : {stem}.pdf")
        else:
            ctx.log(self.name, "fpdf2 non installé → PDF ignoré (imprime le .html en PDF, ou: pip install fpdf2)")
