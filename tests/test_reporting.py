"""Tests de génération de rapport et de scoring."""

import json

from core.context import Context, Finding, Service
from core import reporting
from core.scope import Scope
from core.report_html import generate_html
from core.report_pdf import generate_pdf
from modules.report_module import ReportModule


def _ctx_with_findings():
    ctx = Context()
    h = ctx.add_host("192.168.56.10")
    h.services.append(Service(host="192.168.56.10", port=80, name="http", product="Apache", version="2.4.49"))
    ctx.add_finding(Finding(host="192.168.56.10", title="CVE-X", severity="critical",
                            attack_refs=["T1190"], remediation="Patcher."))
    ctx.add_finding(Finding(host="192.168.56.10", title="Headers", severity="low"))
    return ctx


def test_risk_score_increases_with_severity():
    low = Context(); low.add_finding(Finding(host="h", title="t", severity="low"))
    crit = Context(); crit.add_finding(Finding(host="h", title="t", severity="critical"))
    assert reporting._risk_score(crit)[0] > reporting._risk_score(low)[0]


def test_markdown_report_contains_key_sections(tmp_path):
    ctx = _ctx_with_findings()
    out = reporting.generate(ctx, tmp_path / "r.md", stealth_name="ghost")
    text = out.read_text(encoding="utf-8")
    assert "Résumé exécutif" in text
    assert "MITRE ATT&CK" in text
    assert "Score de risque" in text
    assert "Empreinte & furtivité" in text


def test_markdown_report_states_scope_and_authorization_limits(tmp_path):
    ctx = _ctx_with_findings()
    scope = Scope(hosts={"lab.example"}, allowed_ports={80, 443})

    out = reporting.generate(ctx, tmp_path / "authorized.md", scope=scope)
    text = out.read_text(encoding="utf-8")

    assert "Autorisation et périmètre" in text
    assert "lab.example" in text
    assert "80, 443" in text
    assert "non vérifiée par l'outil" in text
    assert "tests DoS et arrêt de service n'ont pas été exécutés" in text


def test_legacy_robots_finding_has_no_false_remediation_in_markdown(tmp_path):
    ctx = Context()
    ctx.add_finding(Finding(
        host="lab.example", title="Exposition confirmée : /robots.txt", severity="info",
        detail="fichier robots.txt — le contenu correspond à la signature attendue.",
        evidence="https://lab.example/robots.txt", remediation="Restreindre ou supprimer l'accès public à /robots.txt.",
        source_module="http-enum",
    ))

    out = reporting.generate(ctx, tmp_path / "clean.md", scope=Scope(hosts={"lab.example"}))
    text = out.read_text(encoding="utf-8")

    assert "Fichier public standard détecté : /robots.txt" in text
    assert "Restreindre ou supprimer l'accès public à /robots.txt" not in text
    assert "ne constitue pas une vulnérabilité" in text


def test_report_module_passes_scope_to_all_report_generators(tmp_path):
    ctx = Context()
    ctx.add_host("lab.example")
    scope = Scope(hosts={"lab.example"}, allowed_ports={443})
    ReportModule(str(tmp_path / "mission.md"), stealth_name="quiet").run(ctx, scope)

    markdown = (tmp_path / "mission.md").read_text(encoding="utf-8")
    html = (tmp_path / "mission.html").read_text(encoding="utf-8")
    pdf = (tmp_path / "mission.pdf").read_bytes()
    assert "Autorisation et périmètre" in markdown
    assert "Autorisation et périmètre" in html
    assert pdf[:4] == b"%PDF"


def test_html_report_includes_authorization_section(tmp_path):
    ctx = _ctx_with_findings()
    scope = Scope(hosts={"lab.example"}, allowed_ports={80, 443})
    out = generate_html(ctx, tmp_path / "authorized.html", scope=scope)
    text = out.read_text(encoding="utf-8")

    assert "Autorisation et périmètre" in text
    assert "lab.example" in text
    assert "non vérifiée par l&#x27;outil" in text or "non vérifiée par l'outil" in text


def test_pdf_report_accepts_scope_for_authorization_section(tmp_path):
    ctx = _ctx_with_findings()
    scope = Scope(hosts={"lab.example"}, allowed_ports={80, 443})
    out = generate_pdf(ctx, tmp_path / "authorized.pdf", scope=scope)
    assert out is not None
    assert out.read_bytes()[:4] == b"%PDF"


def test_authorization_details_are_explicit_when_scope_is_not_provided():
    details = reporting._authorization_details(Context(), scope=None)
    assert any("scope technique non transmis" in line.lower() for line in details)
    assert any("autorisation légale non vérifiée par l'outil" in line.lower() for line in details)


def test_json_export_is_valid(tmp_path):
    ctx = _ctx_with_findings()
    out = reporting.generate_json(ctx, tmp_path / "r.json", stealth_name="ghost")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["stealth_profile"] == "ghost"
    assert len(data["findings"]) == 2
    assert data["risk_score"] > 0


def test_json_export_discloses_scope_and_normalizes_public_metadata(tmp_path):
    ctx = Context()
    ctx.add_host("lab.example")
    ctx.add_finding(Finding(
        host="lab.example", title="Exposition confirmée : /sitemap.xml", severity="info",
        evidence="https://lab.example/sitemap.xml", remediation="Restreindre ou supprimer l'accès public à /sitemap.xml.",
        source_module="http-enum",
    ))
    scope = Scope(hosts={"lab.example"}, allowed_ports={443})

    out = reporting.generate_json(ctx, tmp_path / "scope.json", scope=scope)
    data = json.loads(out.read_text(encoding="utf-8"))

    assert any("lab.example" in line for line in data["authorization_and_scope"])
    assert data["findings"][0]["title"] == "Fichier public standard détecté : /sitemap.xml"
    assert data["findings"][0]["remediation"] == ""
