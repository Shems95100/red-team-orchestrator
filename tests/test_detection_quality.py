"""Tests de la qualité des détections (item 7) : signatures de contenu + confiance."""

from core.context import Context, Finding
from core import reporting
from modules.enum_http import HttpEnum
from modules.cve_lookup import _impact_summary
from modules.enum_http import (
    looks_like_env, looks_like_git_head, looks_like_phpinfo,
    looks_like_robots, looks_like_server_status,
)


# --- Signatures : un vrai fichier est reconnu, une page d'accueil ne l'est pas --- #
def test_git_head_signature():
    assert looks_like_git_head("ref: refs/heads/main\n") is True
    assert looks_like_git_head("a" * 40) is True          # hash de commit
    assert looks_like_git_head("<!doctype html><html>...") is False


def test_env_signature():
    assert looks_like_env("DB_PASSWORD=secret\nAPI_KEY=abc\n") is True
    assert looks_like_env("<html><body>Welcome</body></html>") is False
    assert looks_like_env("just one line of text") is False


def test_server_status_signature():
    assert looks_like_server_status("Apache Server Status for example.com") is True
    assert looks_like_server_status("<html>home</html>") is False


def test_robots_signature():
    assert looks_like_robots("User-agent: *\nDisallow: /admin\n") is True
    assert looks_like_robots("<!doctype html>User-agent: fake") is False


def test_public_metadata_files_are_not_reported_as_exposures(monkeypatch):
    module = HttpEnum(safe_mode=True)
    monkeypatch.setattr(module.rate, "wait", lambda _host: None)
    monkeypatch.setattr(module.stealth, "sleep", lambda: None)

    def fake_get(url, head=False):
        if url.endswith("robots.txt"):
            return 200, {}, "User-agent: *\nDisallow: /private\n"
        if url.endswith("sitemap.xml"):
            return 200, {}, "<urlset><url><loc>https://lab.local/</loc></url></urlset>"
        return 200, {}, "Contact: mailto:security@lab.local"

    monkeypatch.setattr(module, "_get", fake_get)
    ctx = Context()
    module._check_paths(ctx, "lab.local", "https://lab.local/")

    public_findings = [finding for finding in ctx.findings if finding.source_module == module.name]
    assert len(public_findings) == 3
    assert all(finding.severity == "info" for finding in public_findings)
    assert all(not finding.remediation for finding in public_findings)
    assert all("Exposition confirmée" not in finding.title for finding in public_findings)


def test_phpinfo_signature():
    assert looks_like_phpinfo("<title>phpinfo()</title>") is True
    assert looks_like_phpinfo("<html>nope</html>") is False


def test_cvss_impact_summary_is_explicitly_theoretical():
    cve = {
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "LOW",
                    "availabilityImpact": "NONE",
                }
            }]
        }
    }
    summary = _impact_summary(cve)
    assert "théorique" in summary.lower()
    assert "confidentialité: élevée" in summary
    assert "intégrité: limitée" in summary
    assert "disponibilité: nulle" in summary


# --- La confiance apparaît dans le rapport --------------------------------- #
def test_confidence_shown_in_report(tmp_path):
    ctx = Context()
    ctx.add_finding(Finding(host="h", title="CVE candidate", severity="high",
                            confidence="scanner", source_module="cve-lookup",
                            steps=["vérifier la version", "confirmer l'applicabilité"]))
    out = reporting.generate(ctx, tmp_path / "r.md")
    text = out.read_text(encoding="utf-8")
    assert "SIGNALÉ PAR SCANNER" in text        # libellé de confiance
    assert "Reproduction" in text               # étapes de repro affichées
