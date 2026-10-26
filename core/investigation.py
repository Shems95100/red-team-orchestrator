"""
investigation.py — Moteur d'investigation adaptatif.

Idée directrice (à défendre à l'oral) : un scanner qui s'arrête à la première
détection ne prouve rien. Ce moteur fait l'inverse — chaque *finding* devient
une **hypothèse** qu'il cherche à confirmer, dont il explore le contexte, et à
partir de laquelle il dérive d'autres hypothèses (chaînage), TANT QUE c'est
utile et autorisé. Il s'arrête sur un critère explicite, jamais en boucle.

Ce fichier est volontairement le "cerveau", pas les "mains" :
  - il ORCHESTRE des `Probe` (tests ciblés) ;
  - il ne contient AUCUN payload d'exploitation.
Le corps de chaque `Probe` (le test réel, non destructif, reproductible, adapté
à TON lab autorisé) est à écrire par toi — exactement comme
`modules/check_default_creds.py` est un template que tu adaptes. Voir
`TemplateProbe` en bas de ce fichier.

Garanties structurelles importantes :
  - CHAQUE action passe par `guard(scope, cible)` (frontière technique, pas option).
  - CHAQUE action passe par un contrôle de budget (requêtes/temps) et
    d'autorisation (une étape "sensible" — qui pourrait modifier des données,
    toucher un tiers, ou provoquer une interaction externe — est refusée par
    défaut et exige une autorisation explicite).
  - La boucle TERMINE toujours : un couple (hypothèse, probe) n'est jamais
    rejoué, la profondeur de chaînage est bornée, et budget/temps sont des
    garde-fous ultimes.
"""

from __future__ import annotations

import enum
import itertools
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from core.context import Context, Finding
from core.scope import Scope, ScopeViolation, guard


# --------------------------------------------------------------------------- #
# Vocabulaire : niveaux de confiance et d'impact
# --------------------------------------------------------------------------- #
class Confidence(enum.IntEnum):
    """À quel point on CROIT que la vulnérabilité existe réellement."""
    SCANNER_REPORTED = 1   # un outil/scanner l'a signalée — NON vérifiée, à ne jamais croire sur parole
    PLAUSIBLE = 2          # des indices concordent, mais preuve insuffisante
    CONFIRMED = 3          # vérifiée par un test reproductible


class ImpactStatus(enum.IntEnum):
    """Dans quelle mesure l'IMPACT a été établi (distinct de l'existence)."""
    NONE = 0
    THEORETICAL = 1        # impact plausible mais non démontré
    DEMONSTRATED = 2       # impact prouvé concrètement (souvent une étape "sensible")


class ProbeOutcome(enum.Enum):
    """Résultat d'un test vis-à-vis de l'hypothèse qu'il vérifie."""
    SUPPORTS = "supports"          # va dans le sens de l'hypothèse
    REFUTES = "refutes"            # contredit l'hypothèse (faux positif écarté)
    INCONCLUSIVE = "inconclusive"  # n'apporte pas d'information décisive
    BLOCKED = "blocked"            # n'a pas pu s'exécuter (réseau, précond, etc.)


class StopReason(enum.Enum):
    """Pourquoi l'investigation (ou une branche) s'est arrêtée — toujours explicite."""
    SUFFICIENT_PROOF = "sufficient_proof"            # objectif atteint, on ne surinvestit pas
    NO_PROGRESS = "no_progress"                      # plus aucun test n'apporte d'info
    FRONTIER_EMPTY = "frontier_empty"                # plus aucune hypothèse ouverte
    BUDGET_EXHAUSTED = "budget_exhausted"            # quota de requêtes atteint
    TIME_EXHAUSTED = "time_exhausted"                # délai atteint
    AUTHORIZATION_INSUFFICIENT = "authorization_insufficient"  # étape sensible non autorisée
    SCOPE_BLOCKED = "scope_blocked"                  # cible hors périmètre


class Risk(enum.Enum):
    """Niveau de risque d'un test, pour le gating d'autorisation."""
    SAFE = "safe"            # lecture seule, non destructif, pas d'effet de bord observable
    SENSITIVE = "sensitive"  # pourrait modifier des données, toucher un tiers, déclencher une interaction


# --------------------------------------------------------------------------- #
# Expurgation des preuves ("preuve expurgée des secrets")
# --------------------------------------------------------------------------- #
_SECRET_KV = re.compile(
    r"(?i)\b(pass(?:word|wd)?|pwd|token|secret|api[_-]?key|authorization|cookie|session)\b"
    r"(\s*[=:]\s*)(\S+)"
)
_LONG_BLOB = re.compile(r"\b[A-Za-z0-9+/_\-]{32,}={0,2}\b")


def redact(text: str, keep: int = 3) -> str:
    """Masque les valeurs qui ressemblent à des secrets avant de les stocker.

    Ce n'est pas un coffre-fort cryptographique : c'est une hygiène de rapport,
    pour ne pas recopier mots de passe / tokens / cookies dans un livrable.
    """
    if not text:
        return text

    def _kv(m: re.Match) -> str:
        val = m.group(3)
        shown = val[:keep]
        return f"{m.group(1)}{m.group(2)}{shown}{'…' if len(val) > keep else ''}[expurgé]"

    out = _SECRET_KV.sub(_kv, text)
    out = _LONG_BLOB.sub(lambda m: m.group(0)[:keep] + "…[expurgé]", out)
    return out


# --------------------------------------------------------------------------- #
# Données du graphe d'investigation
# --------------------------------------------------------------------------- #
_ids = itertools.count(1)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{next(_ids):04d}"


@dataclass
class DerivedHypothesis:
    """Proposition de chaînage émise par une probe : 'ceci ouvre peut-être cela'.

    C'est volontairement une *description* abstraite (un type + un titre), pas
    une recette d'attaque. Le moteur décidera si/comment l'explorer, dans la
    limite du périmètre, du budget et de la profondeur.
    """
    vuln_type: str
    title: str
    target: Optional[str] = None            # par défaut : même cible que le parent
    preconditions: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.SCANNER_REPORTED


@dataclass
class Hypothesis:
    """Un nœud du graphe : 'tel actif présente peut-être telle faille'."""
    target: str
    vuln_type: str
    title: str
    confidence: Confidence = Confidence.SCANNER_REPORTED
    impact: ImpactStatus = ImpactStatus.NONE
    preconditions: list[str] = field(default_factory=list)
    parent_id: Optional[str] = None
    depth: int = 0
    id: str = field(default_factory=lambda: _new_id("H"))
    # Cycle de vie
    open: bool = True
    closed_reason: Optional[StopReason] = None
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add_evidence(self, text: str) -> None:
        self.evidence.append(redact(text))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "confidence": self.confidence.name,
            "impact": self.impact.name,
            "preconditions": list(self.preconditions),
            "parent_id": self.parent_id,
            "depth": self.depth,
            "open": self.open,
            "closed_reason": self.closed_reason.value if self.closed_reason else None,
            "evidence": list(self.evidence),
            "notes": list(self.notes),
        }


@dataclass
class TestRecord:
    """Trace d'un test réellement exécuté (reproductibilité + chronologie)."""
    hypothesis_id: str
    probe_name: str
    outcome: ProbeOutcome
    evidence: str = ""
    cost: int = 1
    id: str = field(default_factory=lambda: _new_id("T"))
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hypothesis_id": self.hypothesis_id,
            "probe_name": self.probe_name,
            "outcome": self.outcome.value,
            "evidence": redact(self.evidence),
            "cost": self.cost,
            "ts": self.ts,
        }


@dataclass
class ProbeResult:
    """Ce qu'une probe renvoie au moteur après s'être exécutée."""
    outcome: ProbeOutcome
    new_confidence: Optional[Confidence] = None   # None = laisser le moteur décider
    impact: Optional[ImpactStatus] = None
    evidence: str = ""
    derived: list[DerivedHypothesis] = field(default_factory=list)
    cost: int = 1
    note: str = ""


# --------------------------------------------------------------------------- #
# Contrat d'une "probe" (test ciblé) — à implémenter par toi, pour ton lab
# --------------------------------------------------------------------------- #
class Probe:
    """Interface d'un test d'investigation.

    Le moteur sélectionne une probe pour une hypothèse si `applies_to()` est vrai
    et si `preconditions_met()` est vrai, puis appelle `run()`. `run()` NE DOIT
    émettre aucune requête avant d'avoir appelé `guard(scope, cible)` (le moteur
    le fait aussi en amont, mais la probe doit rester sûre prise isolément).

    `risk` pilote le gating d'autorisation :
      - SAFE      : lecture seule, non destructif → autorisé par défaut ;
      - SENSITIVE : pourrait écrire / toucher un tiers / déclencher une
                    interaction → refusé sauf autorisation explicite.
    """

    name: str = "probe"
    risk: Risk = Risk.SAFE
    #: types de vulnérabilité auxquels la probe s'applique (vide = tous)
    vuln_types: set[str] = set()

    def applies_to(self, hyp: Hypothesis) -> bool:
        return not self.vuln_types or hyp.vuln_type in self.vuln_types

    def preconditions_met(self, hyp: Hypothesis, ctx: Context) -> bool:
        return True

    def run(self, hyp: Hypothesis, ctx: Context, scope: Scope) -> ProbeResult:
        raise NotImplementedError(
            "Implémente ce test pour TON lab autorisé (non destructif, reproductible)."
        )


# --------------------------------------------------------------------------- #
# Budgets, autorisation, critère de preuve
# --------------------------------------------------------------------------- #
@dataclass
class Budget:
    """Limites dures de l'investigation (configurable)."""
    max_requests: int = 200          # nb total d'actions actives
    max_seconds: float = 120.0       # délai mural
    max_tests_per_hypothesis: int = 8
    max_depth: int = 3               # profondeur de chaînage

    _spent: int = 0
    _start: float = field(default_factory=time.time)

    def start(self) -> None:
        self._start = time.time()
        self._spent = 0

    def spend(self, cost: int) -> None:
        self._spent += max(0, cost)

    def requests_exhausted(self) -> bool:
        return self._spent >= self.max_requests

    def can_afford(self, cost: int) -> bool:
        return (self._spent + cost) <= self.max_requests

    def time_exhausted(self) -> bool:
        return (time.time() - self._start) >= self.max_seconds

    @property
    def spent(self) -> int:
        return self._spent


@dataclass
class Authorization:
    """Politique d'autorisation des actions sensibles.

    Par défaut : seules les actions SAFE sont permises. Une action SENSITIVE
    exige soit son niveau dans `allowed`, soit l'aval d'un `approver` (callback
    qui peut, par ex., demander une confirmation humaine). En l'absence des
    deux, l'action est refusée et le moteur s'arrête proprement sur la branche.
    """
    allowed: set[Risk] = field(default_factory=lambda: {Risk.SAFE})
    approver: Optional[Callable[["Probe", "Hypothesis"], bool]] = None

    def permits(self, probe: Probe, hyp: Hypothesis) -> bool:
        if probe.risk in self.allowed:
            return True
        if self.approver is not None:
            try:
                return bool(self.approver(probe, hyp))
            except Exception:  # noqa: BLE001 — un approver qui plante = refus
                return False
        return False


@dataclass
class ProofPolicy:
    """Quand considère-t-on qu'une hypothèse est 'suffisamment' établie ?

    `require_impact=False` (défaut) : on s'arrête de creuser une branche dès que
    la vulnérabilité est CONFIRMED (principe du minimum d'actions nécessaires —
    on a prouvé l'existence, inutile de surinvestir).
    `require_impact=True` : on cherche aussi à DÉMONTRER l'impact (ce qui passe
    en général par une étape SENSITIVE, donc soumise à autorisation).
    """
    require_impact: bool = False

    def is_sufficient(self, hyp: Hypothesis) -> bool:
        if hyp.confidence < Confidence.CONFIRMED:
            return False
        if self.require_impact:
            return hyp.impact >= ImpactStatus.DEMONSTRATED
        return True


# --------------------------------------------------------------------------- #
# Le graphe
# --------------------------------------------------------------------------- #
@dataclass
class InvestigationGraph:
    hypotheses: dict[str, Hypothesis] = field(default_factory=dict)
    tests: list[TestRecord] = field(default_factory=list)

    def add_hypothesis(self, hyp: Hypothesis) -> Hypothesis:
        self.hypotheses[hyp.id] = hyp
        return hyp

    def add_test(self, rec: TestRecord) -> None:
        self.tests.append(rec)

    def open_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self.hypotheses.values() if h.open]

    def children(self, hyp_id: str) -> list[Hypothesis]:
        return [h for h in self.hypotheses.values() if h.parent_id == hyp_id]

    def tests_for(self, hyp_id: str) -> list[TestRecord]:
        return [t for t in self.tests if t.hypothesis_id == hyp_id]

    def summary(self) -> dict:
        hs = list(self.hypotheses.values())
        def count(pred) -> int:
            return sum(1 for h in hs if pred(h))
        return {
            "hypotheses_total": len(hs),
            "confirmed": count(lambda h: h.confidence == Confidence.CONFIRMED),
            "plausible": count(lambda h: h.confidence == Confidence.PLAUSIBLE),
            "scanner_reported": count(lambda h: h.confidence == Confidence.SCANNER_REPORTED),
            "impact_demonstrated": count(lambda h: h.impact == ImpactStatus.DEMONSTRATED),
            "impact_theoretical": count(lambda h: h.impact == ImpactStatus.THEORETICAL),
            "tests_run": len(self.tests),
        }

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "hypotheses": [h.to_dict() for h in self.hypotheses.values()],
            "tests": [t.to_dict() for t in self.tests],
        }


@dataclass
class InvestigationReport:
    graph: InvestigationGraph
    stop_reason: StopReason
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "stop_reason": self.stop_reason.value,
            "notes": list(self.notes),
            **self.graph.to_dict(),
        }


# --------------------------------------------------------------------------- #
# Le moteur
# --------------------------------------------------------------------------- #
class InvestigationEngine:
    """Déroule l'investigation adaptative sur un graphe d'hypothèses.

    Usage :
        eng = InvestigationEngine(scope, probes=[...], budget=Budget(),
                                  authorization=Authorization(), proof=ProofPolicy())
        report = eng.investigate(ctx, seeds=eng.seed_from_findings(ctx))
    """

    def __init__(
        self,
        scope: Scope,
        probes: Iterable[Probe],
        budget: Optional[Budget] = None,
        authorization: Optional[Authorization] = None,
        proof: Optional[ProofPolicy] = None,
    ) -> None:
        self.scope = scope
        self.probes = list(probes)
        self.budget = budget or Budget()
        self.authz = authorization or Authorization()
        self.proof = proof or ProofPolicy()

    # --- amorçage ---------------------------------------------------------- #
    def seed_from_findings(self, ctx: Context) -> list[Hypothesis]:
        """Convertit les findings déjà présents en hypothèses à investiguer.

        Un finding issu d'un scanner/CVE n'est PAS traité comme exploitable : il
        entre au niveau de confiance le plus bas (SCANNER_REPORTED). C'est au
        moteur d'aller le confirmer. ("Ne considère jamais qu'une vulnérabilité
        est exploitable simplement parce qu'un scanner l'a signalée.")
        """
        seeds: list[Hypothesis] = []
        for f in ctx.findings:
            seeds.append(
                Hypothesis(
                    target=f.host,
                    vuln_type=(f.cve or f.source_module or "generic"),
                    title=f.title,
                    confidence=Confidence.SCANNER_REPORTED,
                )
            )
        return seeds

    # --- boucle principale ------------------------------------------------- #
    def investigate(self, ctx: Context, seeds: list[Hypothesis]) -> InvestigationReport:
        graph = InvestigationGraph()
        for s in seeds:
            graph.add_hypothesis(s)

        self.budget.start()
        executed: set[tuple[str, str]] = set()   # (hyp_id, probe_name) déjà joués
        gated: set[tuple[str, str]] = set()       # refusés (autorisation) — à ne pas rejouer
        auth_gated_run = False                    # a-t-on refusé au moins une action sensible ?
        notes: list[str] = []

        ctx.log("investigation", f"Démarrage : {len(seeds)} hypothèse(s) d'amorce.")

        stop: Optional[StopReason] = None
        while stop is None:
            # Garde-fous ultimes : temps et budget.
            if self.budget.time_exhausted():
                stop = StopReason.TIME_EXHAUSTED
                break
            if self.budget.requests_exhausted():
                stop = StopReason.BUDGET_EXHAUSTED
                break

            action = self._select_action(graph, ctx, executed, gated)
            if action is None:
                stop = self._stop_reason_when_idle(graph, auth_gated_run)
                break

            hyp, probe = action

            # 1) Scope : frontière technique, vérifiée À CHAQUE action.
            try:
                guard(self.scope, hyp.target)
            except ScopeViolation as e:
                hyp.open = False
                hyp.closed_reason = StopReason.SCOPE_BLOCKED
                hyp.notes.append(f"Hors périmètre : {e}")
                ctx.log("investigation", f"REFUS périmètre : {hyp.target} ({hyp.id})")
                continue

            # 2) Autorisation : une étape sensible non autorisée n'est pas jouée.
            if not self.authz.permits(probe, hyp):
                gated.add((hyp.id, probe.name))
                auth_gated_run = True
                hyp.notes.append(
                    f"Test '{probe.name}' ({probe.risk.value}) non autorisé — "
                    f"étape sensible en attente d'autorisation."
                )
                ctx.log("investigation",
                        f"GATE autorisation : '{probe.name}' sur {hyp.id} (risque {probe.risk.value})")
                continue

            # 3) Budget pour cette action précise.
            if not self.budget.can_afford(1):
                stop = StopReason.BUDGET_EXHAUSTED
                break

            # 4) Exécution du test.
            executed.add((hyp.id, probe.name))
            try:
                result = probe.run(hyp, ctx, self.scope)
            except ScopeViolation as e:
                hyp.open = False
                hyp.closed_reason = StopReason.SCOPE_BLOCKED
                hyp.notes.append(f"Hors périmètre (probe) : {e}")
                continue
            except Exception as e:  # noqa: BLE001 — une probe qui plante ne tue pas la mission
                result = ProbeResult(ProbeOutcome.BLOCKED, note=f"erreur: {e!r}")

            self.budget.spend(result.cost)
            graph.add_test(TestRecord(
                hypothesis_id=hyp.id,
                probe_name=probe.name,
                outcome=result.outcome,
                evidence=result.evidence,
                cost=result.cost,
            ))
            ctx.log("investigation",
                    f"{probe.name} → {result.outcome.value} sur {hyp.id} ({hyp.title})")

            # 5) Mise à jour de l'hypothèse selon le résultat (logique adaptative).
            self._apply_result(graph, ctx, hyp, result)

            # 6) Critère d'arrêt de BRANCHE : minimum d'actions nécessaires.
            if hyp.open and self.proof.is_sufficient(hyp):
                hyp.open = False
                hyp.closed_reason = StopReason.SUFFICIENT_PROOF
                self._emit_finding(ctx, hyp)
                ctx.log("investigation", f"Preuve suffisante : {hyp.id} clôturée.")

            # 7) Trop de tests sur une même hypothèse sans conclusion → on la ferme.
            if hyp.open and len(graph.tests_for(hyp.id)) >= self.budget.max_tests_per_hypothesis:
                hyp.open = False
                hyp.closed_reason = StopReason.NO_PROGRESS
                hyp.notes.append("Quota de tests par hypothèse atteint sans confirmation.")

        report = InvestigationReport(graph=graph, stop_reason=stop, notes=notes)
        # On expose le graphe pour le rapport (JSON/MD/HTML). Voir investigation_module.
        setattr(ctx, "investigation", report.to_dict())
        ctx.log("investigation", f"Arrêt : {stop.value} — {graph.summary()}")
        return report

    # --- sélection de la prochaine action ---------------------------------- #
    def _select_action(
        self,
        graph: InvestigationGraph,
        ctx: Context,
        executed: set[tuple[str, str]],
        gated: set[tuple[str, str]],
    ) -> Optional[tuple[Hypothesis, Probe]]:
        """Choisit le prochain couple (hypothèse, probe) à jouer.

        Priorité : les hypothèses les plus proches d'être prouvées d'abord
        (confiance décroissante), puis les moins profondes — pour confirmer vite
        avec le moins d'actions possible. Ne renvoie jamais un couple déjà joué
        ou déjà refusé (garantit la terminaison).
        """
        candidates = sorted(
            graph.open_hypotheses(),
            key=lambda h: (-int(h.confidence), h.depth),
        )
        for hyp in candidates:
            for probe in self.probes:
                key = (hyp.id, probe.name)
                if key in executed or key in gated:
                    continue
                if not probe.applies_to(hyp):
                    continue
                if not probe.preconditions_met(hyp, ctx):
                    continue
                return hyp, probe
        return None

    def _stop_reason_when_idle(self, graph: InvestigationGraph, auth_gated_run: bool) -> StopReason:
        open_hyps = graph.open_hypotheses()
        if not open_hyps:
            # Toutes les hypothèses sont closes : preuve suffisante si au moins
            # une l'a été ainsi, sinon frontière épuisée.
            if any(h.closed_reason == StopReason.SUFFICIENT_PROOF
                   for h in graph.hypotheses.values()):
                return StopReason.SUFFICIENT_PROOF
            return StopReason.FRONTIER_EMPTY
        # Il reste des hypothèses ouvertes mais plus rien à jouer dessus.
        if auth_gated_run:
            return StopReason.AUTHORIZATION_INSUFFICIENT
        return StopReason.NO_PROGRESS

    # --- application d'un résultat ----------------------------------------- #
    def _apply_result(
        self,
        graph: InvestigationGraph,
        ctx: Context,
        hyp: Hypothesis,
        result: ProbeResult,
    ) -> None:
        if result.evidence:
            hyp.add_evidence(result.evidence)
        if result.note:
            hyp.notes.append(result.note)

        if result.outcome == ProbeOutcome.REFUTES:
            # Faux positif écarté : on ferme la branche, c'est un résultat utile.
            hyp.open = False
            hyp.closed_reason = StopReason.SUFFICIENT_PROOF
            hyp.notes.append("Hypothèse réfutée par un test (faux positif écarté).")
            return

        if result.outcome == ProbeOutcome.SUPPORTS:
            if result.new_confidence is not None:
                hyp.confidence = max(hyp.confidence, result.new_confidence)
            else:
                # Montée d'un cran : SCANNER_REPORTED → PLAUSIBLE → CONFIRMED
                hyp.confidence = Confidence(min(int(Confidence.CONFIRMED), int(hyp.confidence) + 1))

        if result.impact is not None:
            hyp.impact = max(hyp.impact, result.impact)

        # Chaînage : les hypothèses dérivées proposées par la probe, bornées par
        # la profondeur et filtrées par le périmètre.
        for d in result.derived:
            child_depth = hyp.depth + 1
            if child_depth > self.budget.max_depth:
                hyp.notes.append(f"Chaînage ignoré (profondeur max) : {d.title}")
                continue
            target = d.target or hyp.target
            if not self.scope.is_in_scope(target):
                hyp.notes.append(f"Chaînage hors périmètre ignoré : {d.title} ({target})")
                continue
            child = Hypothesis(
                target=target,
                vuln_type=d.vuln_type,
                title=d.title,
                confidence=d.confidence,
                preconditions=list(d.preconditions),
                parent_id=hyp.id,
                depth=child_depth,
            )
            graph.add_hypothesis(child)
            ctx.log("investigation", f"Chaînage : {hyp.id} → {child.id} ({child.title})")

    # --- sortie : un finding confirmé rejoint le rapport existant ---------- #
    def _emit_finding(self, ctx: Context, hyp: Hypothesis) -> None:
        if hyp.confidence < Confidence.CONFIRMED:
            return
        sev = "high" if hyp.impact >= ImpactStatus.DEMONSTRATED else "medium"
        ctx.add_finding(Finding(
            host=hyp.target,
            title=f"[confirmé] {hyp.title}",
            severity=sev,
            confidence="confirmed",
            detail=(f"Vulnérabilité confirmée par investigation adaptative. "
                    f"Impact : {hyp.impact.name.lower()}."),
            evidence=" | ".join(hyp.evidence[-3:]),
            source_module="investigation",
        ))


# --------------------------------------------------------------------------- #
# TEMPLATE — copie-moi pour écrire une vraie probe pour TON lab autorisé
# --------------------------------------------------------------------------- #
class TemplateProbe(Probe):
    """Squelette d'une probe. Copie ce fichier-pattern (comme check_default_creds).

    Règles d'or d'une probe correcte :
      - NON destructive et reproductible (un oracle booléen, pas une attaque) ;
      - appelle `guard(scope, cible)` avant toute requête réseau ;
      - renvoie un `ProbeResult` honnête : SUPPORTS seulement si l'indice est réel,
        REFUTES si l'hypothèse est écartée, INCONCLUSIVE sinon ;
      - fixe `risk = Risk.SENSITIVE` dès que l'action pourrait écrire des données,
        toucher un tiers ou déclencher une interaction externe → elle sera alors
        soumise à autorisation.
    """

    name = "template-probe"
    risk = Risk.SAFE
    vuln_types: set[str] = set()  # ex. {"cors", "tls"} ; vide = s'applique à tout

    def applies_to(self, hyp: Hypothesis) -> bool:
        return super().applies_to(hyp)

    def run(self, hyp: Hypothesis, ctx: Context, scope: Scope) -> ProbeResult:
        guard(scope, hyp.target)   # réflexe : périmètre d'abord
        # TODO(toi) : implémente ici le test non destructif adapté à ton lab,
        #             puis renvoie un ProbeResult reflétant fidèlement le constat.
        raise NotImplementedError("Écris le corps de cette probe pour ton lab autorisé.")
