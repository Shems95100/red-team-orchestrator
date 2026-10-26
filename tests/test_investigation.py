"""
test_investigation.py — Prouve le comportement du moteur d'investigation.

Ces tests utilisent des probes MOCK (scriptées, aucune requête réseau, aucun
payload) : on teste le MOTEUR, pas des exploits. On démontre que le moteur :
  - poursuit l'investigation APRÈS une première détection (confirmation + chaînage) ;
  - ADAPTE ses tests aux résultats (réfutation = branche élaguée ; support = suite) ;
  - S'ARRÊTE correctement : budget, autorisation insuffisante, hors périmètre,
    absence de progression, preuve suffisante.
"""

from __future__ import annotations

import ipaddress

import pytest

from core.context import Context, Finding
from core.scope import Scope, ScopeViolation, guard
from core.investigation import (
    Authorization,
    Budget,
    Confidence,
    DerivedHypothesis,
    Hypothesis,
    ImpactStatus,
    InvestigationEngine,
    Probe,
    ProbeOutcome,
    ProbeResult,
    ProofPolicy,
    Risk,
    StopReason,
    redact,
)


# --------------------------------------------------------------------------- #
# Outillage de test
# --------------------------------------------------------------------------- #
def lab_scope() -> Scope:
    s = Scope(
        hosts={"lab.local"},
        networks=[ipaddress.ip_network("192.168.56.0/24")],
    )
    # Le scope durci résout les noms à chaque action (anti-rebinding). En lab,
    # lab.local résout vers une IP du réseau autorisé (comme via /etc/hosts) —
    # on injecte ce résolveur pour des tests déterministes, sans réseau réel.
    s.resolver = lambda host: ["192.168.56.10"]
    return s


class ScriptedProbe(Probe):
    """Probe mock : renvoie un résultat scripté et enregistre ses appels."""

    def __init__(self, name, result, vuln_types=None, risk=Risk.SAFE):
        self.name = name
        self._result = result            # ProbeResult OU callable(hyp)->ProbeResult
        self.vuln_types = set(vuln_types or [])
        self.risk = risk
        self.calls: list[str] = []

    def run(self, hyp, ctx, scope):
        self.calls.append(hyp.id)
        guard(scope, hyp.target)         # une probe reste sûre prise isolément
        return self._result(hyp) if callable(self._result) else self._result


def run_engine(scope, probes, seeds, **kw):
    eng = InvestigationEngine(scope=scope, probes=probes, **kw)
    ctx = Context()
    report = eng.investigate(ctx, seeds)
    return ctx, report


# --------------------------------------------------------------------------- #
# 1. Le moteur POURSUIT après la première détection
# --------------------------------------------------------------------------- #
def test_continue_after_first_detection():
    probe_confirm = ScriptedProbe(
        "confirm-idor",
        ProbeResult(
            ProbeOutcome.SUPPORTS,
            new_confidence=Confidence.CONFIRMED,
            evidence="réponse différentielle reproductible",
            derived=[DerivedHypothesis(vuln_type="privdata",
                                       title="accès à des données via l'IDOR confirmé")],
        ),
        vuln_types={"idor"},
    )
    probe_followup = ScriptedProbe(
        "followup-privdata",
        ProbeResult(ProbeOutcome.SUPPORTS, new_confidence=Confidence.CONFIRMED),
        vuln_types={"privdata"},
    )
    seeds = [Hypothesis(target="lab.local", vuln_type="idor",
                        title="IDOR possible sur /api/users")]

    ctx, report = run_engine(lab_scope(), [probe_confirm, probe_followup], seeds)

    # Première détection confirmée, PUIS une hypothèse dérivée a été investiguée.
    assert report.graph.summary()["hypotheses_total"] == 2
    assert report.graph.summary()["tests_run"] == 2
    assert probe_followup.calls, "le moteur aurait dû enchaîner sur l'hypothèse dérivée"
    # La dérivée est bien rattachée à son parent (graphe, pas liste plate).
    parents = {h.parent_id for h in report.graph.hypotheses.values() if h.parent_id}
    assert len(parents) == 1
    assert report.stop_reason == StopReason.SUFFICIENT_PROOF


# --------------------------------------------------------------------------- #
# 2. Le moteur ADAPTE ses tests aux résultats
# --------------------------------------------------------------------------- #
def test_adapts_refuted_branch_is_pruned():
    refute_a = ScriptedProbe("refute-a", ProbeResult(ProbeOutcome.REFUTES), vuln_types={"a"})
    followup_a = ScriptedProbe("followup-a", ProbeResult(ProbeOutcome.SUPPORTS), vuln_types={"a"})
    support_b = ScriptedProbe(
        "support-b",
        ProbeResult(ProbeOutcome.SUPPORTS, new_confidence=Confidence.CONFIRMED,
                    derived=[DerivedHypothesis(vuln_type="bchild", title="suite de b")]),
        vuln_types={"b"},
    )
    child_b = ScriptedProbe("child-b", ProbeResult(ProbeOutcome.SUPPORTS,
                                                   new_confidence=Confidence.CONFIRMED),
                            vuln_types={"bchild"})
    seeds = [
        Hypothesis(target="lab.local", vuln_type="a", title="piste A (faux positif)"),
        Hypothesis(target="lab.local", vuln_type="b", title="piste B (réelle)"),
    ]

    ctx, report = run_engine(lab_scope(), [refute_a, followup_a, support_b, child_b], seeds)

    # Branche A réfutée : AUCUN test de suivi ne doit avoir tourné dessus.
    assert followup_a.calls == [], "une branche réfutée ne doit pas être approfondie"
    # Branche B supportée : elle a bien été étendue puis investiguée.
    assert child_b.calls, "une branche supportée doit déclencher ses tests de suivi"
    # Aucune hypothèse dérivée de A ; une seule dérivée (celle de B).
    assert report.graph.summary()["hypotheses_total"] == 3


# --------------------------------------------------------------------------- #
# 3. Arrêt sur BUDGET
# --------------------------------------------------------------------------- #
def test_stops_on_budget_exhausted():
    probe = ScriptedProbe("p", ProbeResult(ProbeOutcome.SUPPORTS), vuln_types={"x"})
    seeds = [
        Hypothesis(target="lab.local", vuln_type="x", title="h1"),
        Hypothesis(target="lab.local", vuln_type="x", title="h2"),
    ]
    ctx, report = run_engine(lab_scope(), [probe], seeds, budget=Budget(max_requests=1))

    assert report.stop_reason == StopReason.BUDGET_EXHAUSTED
    assert report.graph.summary()["tests_run"] == 1


# --------------------------------------------------------------------------- #
# 4. Arrêt sur AUTORISATION insuffisante (étape sensible non autorisée)
# --------------------------------------------------------------------------- #
def test_stops_on_insufficient_authorization():
    confirm = ScriptedProbe(
        "confirm-sqli",
        ProbeResult(ProbeOutcome.SUPPORTS, new_confidence=Confidence.CONFIRMED,
                    impact=ImpactStatus.THEORETICAL),
        vuln_types={"sqli"}, risk=Risk.SAFE,
    )
    demonstrate = ScriptedProbe(
        "demonstrate-sqli-impact",
        ProbeResult(ProbeOutcome.SUPPORTS, impact=ImpactStatus.DEMONSTRATED),
        vuln_types={"sqli"}, risk=Risk.SENSITIVE,       # étape sensible
    )
    seeds = [Hypothesis(target="lab.local", vuln_type="sqli", title="SQLi possible")]

    # On EXIGE la démonstration d'impact, mais on n'autorise QUE le SAFE.
    ctx, report = run_engine(
        lab_scope(), [confirm, demonstrate], seeds,
        authorization=Authorization(allowed={Risk.SAFE}),
        proof=ProofPolicy(require_impact=True),
    )

    assert report.stop_reason == StopReason.AUTHORIZATION_INSUFFICIENT
    assert demonstrate.calls == [], "l'étape sensible ne doit pas être jouée sans autorisation"
    h = next(iter(report.graph.hypotheses.values()))
    assert h.confidence == Confidence.CONFIRMED      # vuln confirmée...
    assert h.impact == ImpactStatus.THEORETICAL      # ...mais impact NON démontré
    assert h.open is True                            # branche laissée en attente d'autorisation


def test_authorized_sensitive_step_demonstrates_impact():
    confirm = ScriptedProbe(
        "confirm-sqli",
        ProbeResult(ProbeOutcome.SUPPORTS, new_confidence=Confidence.CONFIRMED,
                    impact=ImpactStatus.THEORETICAL),
        vuln_types={"sqli"},
    )
    demonstrate = ScriptedProbe(
        "demonstrate-sqli-impact",
        ProbeResult(ProbeOutcome.SUPPORTS, impact=ImpactStatus.DEMONSTRATED),
        vuln_types={"sqli"}, risk=Risk.SENSITIVE,
    )
    seeds = [Hypothesis(target="lab.local", vuln_type="sqli", title="SQLi possible")]

    ctx, report = run_engine(
        lab_scope(), [confirm, demonstrate], seeds,
        authorization=Authorization(approver=lambda p, h: True),   # autorisation explicite
        proof=ProofPolicy(require_impact=True),
    )

    assert report.stop_reason == StopReason.SUFFICIENT_PROOF
    assert demonstrate.calls, "l'étape sensible autorisée doit s'exécuter"
    h = next(iter(report.graph.hypotheses.values()))
    assert h.impact == ImpactStatus.DEMONSTRATED
    # Un finding confirmé a rejoint le rapport existant.
    assert any(f.source_module == "investigation" for f in ctx.findings)


# --------------------------------------------------------------------------- #
# 5. Arrêt / refus sur PÉRIMÈTRE
# --------------------------------------------------------------------------- #
def test_out_of_scope_target_is_never_tested():
    probe = ScriptedProbe("p", ProbeResult(ProbeOutcome.SUPPORTS), vuln_types={"x"})
    seeds = [Hypothesis(target="evil.example", vuln_type="x", title="cible interdite")]

    ctx, report = run_engine(lab_scope(), [probe], seeds)

    assert probe.calls == [], "aucune action ne doit viser une cible hors périmètre"
    assert report.graph.summary()["tests_run"] == 0
    h = next(iter(report.graph.hypotheses.values()))
    assert h.open is False
    assert h.closed_reason == StopReason.SCOPE_BLOCKED


def test_chaining_cannot_escape_scope():
    # Une probe "confirme" et tente de dériver une cible HORS périmètre.
    probe = ScriptedProbe(
        "confirm-and-pivot",
        ProbeResult(ProbeOutcome.SUPPORTS, new_confidence=Confidence.CONFIRMED,
                    derived=[DerivedHypothesis(vuln_type="y", title="pivot interdit",
                                               target="evil.example")]),
        vuln_types={"x"},
    )
    seeds = [Hypothesis(target="lab.local", vuln_type="x", title="point d'entrée")]

    ctx, report = run_engine(lab_scope(), [probe], seeds)

    # La dérivation hors périmètre est refusée : pas de nœud enfant créé.
    assert report.graph.summary()["hypotheses_total"] == 1


# --------------------------------------------------------------------------- #
# 6. Arrêt sur ABSENCE DE PROGRESSION (pas de boucle infinie)
# --------------------------------------------------------------------------- #
def test_stops_on_no_progress():
    probe = ScriptedProbe("inconclusive", ProbeResult(ProbeOutcome.INCONCLUSIVE),
                          vuln_types={"x"})
    seeds = [Hypothesis(target="lab.local", vuln_type="x", title="indécis")]

    ctx, report = run_engine(lab_scope(), [probe], seeds)

    assert report.stop_reason == StopReason.NO_PROGRESS
    assert report.graph.summary()["tests_run"] == 1


# --------------------------------------------------------------------------- #
# 7. Amorçage depuis les findings + ne JAMAIS croire un scanner sur parole
# --------------------------------------------------------------------------- #
def test_seed_from_findings_starts_at_lowest_confidence():
    ctx = Context()
    ctx.add_finding(Finding(host="lab.local", title="Apache 2.4.49 — CVE-2021-41773",
                            severity="high", source_module="cve", cve="CVE-2021-41773"))
    eng = InvestigationEngine(scope=lab_scope(), probes=[])
    seeds = eng.seed_from_findings(ctx)

    assert len(seeds) == 1
    assert seeds[0].confidence == Confidence.SCANNER_REPORTED  # à confirmer, pas "exploitable"


def test_no_probes_runs_nothing_but_records_hypotheses():
    ctx = Context()
    ctx.add_finding(Finding(host="lab.local", title="piste", source_module="cve"))
    eng = InvestigationEngine(scope=lab_scope(), probes=[])
    report = eng.investigate(ctx, eng.seed_from_findings(ctx))

    assert report.graph.summary()["tests_run"] == 0
    assert report.graph.summary()["hypotheses_total"] == 1
    assert hasattr(ctx, "investigation")  # graphe exposé pour le rapport


# --------------------------------------------------------------------------- #
# 8. Expurgation des preuves
# --------------------------------------------------------------------------- #
def test_redact_masks_secrets():
    raw = "login ok password=SuperSecret123 token: abcdef0123456789abcdef0123456789aa"
    out = redact(raw)
    assert "SuperSecret123" not in out
    assert "abcdef0123456789abcdef0123456789aa" not in out
    assert "[expurgé]" in out
