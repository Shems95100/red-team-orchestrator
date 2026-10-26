"""
investigation_module.py — Branche le moteur d'investigation dans le pipeline.

Phase "vuln" : une fois que la recon et le matching CVE ont produit des findings
"bruts" (niveau scanner), ce module les reprend comme HYPOTHÈSES et lance le
moteur d'investigation adaptatif pour tenter de les confirmer, explorer leur
contexte et dériver des pistes chaînées — dans la limite du périmètre, du budget
et des autorisations.

IMPORTANT : ce module n'embarque AUCUNE probe par défaut. Tu lui injectes la
liste de TES probes (écrites pour ton lab autorisé, à partir de
`core.investigation.TemplateProbe`). Sans probe, il se contente de transformer
les findings en hypothèses "à confirmer" et de le consigner — honnête et sûr.
"""

from __future__ import annotations

from typing import Iterable, Optional

from core.context import Context
from core.investigation import (
    Authorization,
    Budget,
    InvestigationEngine,
    Probe,
    ProofPolicy,
)
from core.scope import Scope
from modules.base import Module


class InvestigationModule(Module):
    name = "investigation"
    phase = "vuln"
    attack_refs = ["T1595", "T1190"]  # Active Scanning / Exploit Public-Facing App

    def __init__(
        self,
        probes: Optional[Iterable[Probe]] = None,
        budget: Optional[Budget] = None,
        authorization: Optional[Authorization] = None,
        proof: Optional[ProofPolicy] = None,
    ) -> None:
        self.probes = list(probes or [])
        self.budget = budget
        self.authorization = authorization
        self.proof = proof

    def should_run(self, ctx: Context) -> bool:
        # Il y a quelque chose à investiguer s'il existe déjà des findings
        # (issus de la recon / du matching CVE) ou des services identifiés.
        return bool(ctx.findings) or bool(ctx.all_services())

    def run(self, ctx: Context, scope: Scope) -> None:
        engine = InvestigationEngine(
            scope=scope,
            probes=self.probes,
            budget=self.budget,
            authorization=self.authorization,
            proof=self.proof,
        )
        seeds = engine.seed_from_findings(ctx)
        if not seeds:
            ctx.log(self.name, "Aucun finding à investiguer pour l'instant.")
            return
        if not self.probes:
            ctx.log(self.name,
                    f"{len(seeds)} hypothèse(s) à confirmer, mais aucune probe "
                    f"enregistrée — rien n'est testé (ajoute tes probes de lab).")
        report = engine.investigate(ctx, seeds)
        ctx.log(self.name,
                f"Investigation terminée ({report.stop_reason.value}). "
                f"Graphe disponible dans ctx.investigation pour le rapport.")
