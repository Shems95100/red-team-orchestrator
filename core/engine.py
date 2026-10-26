"""
engine.py — Le moteur d'orchestration (le "cerveau" du bot).

Il ne tire PAS une liste d'exploits à l'aveugle. Il déroule les phases dans
l'ordre, et à chaque phase il ne lance que les modules qui ont quelque chose à
faire selon ce qui a déjà été découvert (should_run). C'est ce comportement
adaptatif que tu mets en avant à l'oral : "le bot découvre, puis décide".
"""

from __future__ import annotations

from core.context import Context
from core.scope import Scope, ScopeViolation
from modules.base import Module, PHASE_ORDER


class Engine:
    def __init__(self, scope: Scope, modules: list[Module]):
        self.scope = scope
        self.modules = modules

    def run(self, targets: list[str]) -> Context:
        ctx = Context()

        # Garde-fou global : on filtre les cibles AVANT de commencer.
        valid = []
        for t in targets:
            if self.scope.is_in_scope(t):
                valid.append(t)
            else:
                print(f"  [engine] Cible ignorée (hors périmètre) : {t}")
        if not valid:
            print("  [engine] Aucune cible dans le périmètre. Vérifie scope.yaml.")
            return ctx

        for t in valid:
            ctx.add_host(t if _looks_like_ip(t) else t, hostname="" if _looks_like_ip(t) else t)

        ctx.log("engine", f"Démarrage mission sur {len(valid)} cible(s) : {', '.join(valid)}")

        # On déroule phase par phase. Une interruption (Ctrl+C) reste propre :
        # on arrête le travail en cours mais on génère quand même le rapport partiel.
        try:
            for phase in PHASE_ORDER:
                if phase == "report":
                    continue  # le reporting est joué à la toute fin (même si interruption)
                phase_modules = [m for m in self.modules if m.phase == phase]
                if not phase_modules:
                    continue
                ctx.log("engine", f"=== Phase : {phase} ===")
                for module in phase_modules:
                    try:
                        if not module.is_active():
                            if getattr(module, "phase", None) == "exploit":
                                if getattr(module, "dry_run", False):
                                    ctx.log("engine", f"(module '{module.name}' en mode dry-run, exploitation bloquée)")
                                else:
                                    ctx.log("engine", f"(module '{module.name}' exploit non autorisé, ignoré)")
                            continue
                        if module.should_run(ctx):
                            ctx.log("engine", f"-> module '{module.name}'")
                            module.run(ctx, self.scope)
                        else:
                            ctx.log("engine", f"(module '{module.name}' sans objet, ignoré)")
                    except ScopeViolation as e:
                        ctx.log("engine", f"REFUS périmètre dans '{module.name}' : {e}")
                    except Exception as e:  # noqa: BLE001 — un module ne doit pas tuer la mission
                        ctx.log("engine", f"Erreur dans '{module.name}' : {e!r}")
        except KeyboardInterrupt:
            ctx.log("engine", "Interruption (Ctrl+C) — arrêt propre, génération du rapport partiel.")

        # Phase report : toujours jouée, même après interruption.
        self._run_reports(ctx)
        ctx.log("engine", "Mission terminée.")
        return ctx

    def _run_reports(self, ctx: Context) -> None:
        for module in [m for m in self.modules if m.phase == "report"]:
            try:
                ctx.log("engine", f"=== Phase : report ===")
                ctx.log("engine", f"-> module '{module.name}'")
                module.run(ctx, self.scope)
            except Exception as e:  # noqa: BLE001
                ctx.log("engine", f"Erreur dans le reporting '{module.name}' : {e!r}")


def _looks_like_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
