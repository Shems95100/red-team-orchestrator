"""Report which higher-impact checks were deliberately omitted in audit mode."""

from __future__ import annotations

from core.context import Context, Finding
from core.scope import Scope
from modules.base import Module


class AuditNotice(Module):
    name = "audit-notice"
    phase = "vuln"

    def should_run(self, ctx: Context) -> bool:
        return bool(ctx.hosts)

    def run(self, ctx: Context, scope: Scope) -> None:
        for host in ctx.hosts:
            ctx.add_finding(Finding(
                host=host,
                title="Contrôles destructifs volontairement non exécutés",
                severity="info",
                confidence="firm",
                detail=(
                    "Mode audit prudent : aucun exploit, test DoS, arrêt de service, "
                    "brute force ou validation modifiant l'état n'a été lancé. "
                    "Les impacts de disponibilité ne sont donc pas démontrés ; "
                    "les failles signalées reposent uniquement sur les indices observés."
                ),
                evidence="mode=audit; destructive_checks=not_run",
                source_module=self.name,
                remediation="Planifier toute validation d'impact séparément, sur un environnement de préproduction autorisé.",
                steps=["Examiner les risques théoriques remontés dans le rapport.", "Ne valider les impacts qu'en préproduction avec une autorisation dédiée."],
            ))
