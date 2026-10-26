"""
base.py — L'interface commune à tous les modules.

Chaque capacité du bot (recon, énum web, matching CVE, module d'exploit...) est
une sous-classe de Module. Le moteur demande à chaque module `should_run()` en
fonction de l'état courant, puis appelle `run()`. C'est ce design qui rend le bot
"adaptatif" : un module web ne se déclenche que si un service web a été trouvé.

Pour ajouter une capacité au bot, tu crées un nouveau fichier dans modules/,
tu hérites de Module, et tu l'enregistres dans main.py. C'est tout.
"""

from __future__ import annotations

from core.context import Context
from core.exploit_policy import ExploitPolicy
from core.scope import Scope


class Module:
    #: Nom court affiché dans les logs et le rapport
    name: str = "module"
    #: Phase : "recon" | "enum" | "vuln" | "exploit" | "post" | "report"
    phase: str = "recon"
    #: Techniques MITRE ATT&CK couvertes par ce module (IDs du registre core.attack)
    attack_refs: list[str] = []
    #: Autorisation explicite requise pour les modules riskés (ex. exploit).
    enabled: bool = True
    #: Mode validation seule : on ne déploie aucun PoC de façon active.
    dry_run: bool = False
    #: Seuil minimal de gravité pour déclencher un PoC d'exploitation autorisé.
    min_severity: str = "high"
    #: Politique explicite de validation avant exploitation.
    exploit_policy: ExploitPolicy | None = None

    def is_active(self) -> bool:
        """True si le module est autorisé à s'exécuter dans le cadre courant."""
        if not self.enabled:
            return False
        if self.phase == "exploit" and self.dry_run:
            return False
        return True

    def has_serious_finding(self, ctx: Context, keywords: list[str] | tuple[str, ...] | str | None = None) -> bool:
        """Vrai si le contexte contient une vulnérabilité sérieuse de type attendu."""
        if not ctx.findings:
            return False

        policy = self.exploit_policy or ExploitPolicy(min_severity=self.min_severity, require_evidence=True,
                                                     allow_exploit=True)
        return policy.can_exploit(ctx, keywords=keywords)

    def has_service_ready_for_exploit(self, ctx: Context, service_names: list[str] | tuple[str, ...], ports: list[int] | tuple[int, ...],
                                     keywords: list[str] | tuple[str, ...] | str | None = None) -> bool:
        """Active un PoC démonstratif si le service est exposé et le mode exploitation est autorisé."""
        services = [
            svc for svc in ctx.all_services()
            if (svc.name.lower() in {name.lower() for name in service_names} or svc.port in ports)
        ]
        if not services:
            return False

        if self.exploit_policy and self.exploit_policy.allow_exploit:
            if self.has_serious_finding(ctx, keywords):
                return True
            # En mode exploitation active, on accepte aussi les services exposés avec un
            # score host suffisant pour maintenir une démonstration offensive utile.
            return any(ctx.host_priority(svc.host) >= 6 for svc in services)

        return self.has_serious_finding(ctx, keywords)

    def should_run(self, ctx: Context) -> bool:
        """
        Décide si ce module a quelque chose à faire vu l'état courant.
        Ex. un module HTTP renvoie True seulement si un service http existe.
        Par défaut : toujours.
        """
        return True

    def run(self, ctx: Context, scope: Scope) -> None:
        """
        Exécute le module. DOIT appeler core.scope.guard(scope, cible) avant
        toute action réseau contre une cible.
        """
        raise NotImplementedError


# Ordre canonique d'exécution des phases (logique PTES simplifiée).
PHASE_ORDER = ["recon", "enum", "vuln", "exploit", "post", "report"]
