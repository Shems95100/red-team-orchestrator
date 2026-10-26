"""Tests des modules : déclenchement adaptatif + génération HTML/PDF."""

from core.context import Context, Finding, Service
from core.report_html import generate_html
from core.report_pdf import generate_pdf
from main import build_modules
from modules.ctf_crypto import CryptoTriage
from modules.ctf_osint import OsintTriage
from modules.forensics_triage import ForensicsTriage
from modules.reverse_triage import ReverseTriage
from modules.web_ctf import WebCtf
from modules.enum_smb import SmbEnum
from modules.enum_http import HttpEnum
from modules.enum_ad import AdEnum
from modules.enum_winrm import WinRmEnum
from modules.enum_identity import IdentityEnum
from modules.privilege_path import PrivilegePath


def _ctx_web():
    ctx = Context()
    h = ctx.add_host("10.0.0.5")
    h.services.append(Service(host="10.0.0.5", port=80, name="http"))
    return ctx


def _ctx_smb():
    ctx = Context()
    h = ctx.add_host("10.0.0.6")
    h.services.append(Service(host="10.0.0.6", port=445, name="microsoft-ds"))
    return ctx


def test_http_enum_triggers_on_web():
    assert HttpEnum().should_run(_ctx_web()) is True
    assert HttpEnum().should_run(_ctx_smb()) is False


def test_http_audit_mode_uses_only_low_impact_paths():
    module = HttpEnum(safe_mode=True)
    paths = {path for path, *_ in module.paths}
    assert paths == {"robots.txt", "sitemap.xml", ".well-known/security.txt"}
    assert ".env" not in paths
    assert ".git/HEAD" not in paths


def test_web_ctf_audit_mode_avoids_sensitive_paths():
    module = WebCtf(safe_mode=True)
    assert set(module.paths) == {"robots.txt", "sitemap.xml", ".well-known/security.txt"}
    assert "backup" not in module.paths
    assert "admin" not in module.paths


def test_smb_enum_triggers_on_smb():
    assert SmbEnum().should_run(_ctx_smb()) is True
    assert SmbEnum().should_run(_ctx_web()) is False


def test_ad_enum_triggers_on_ad_ports():
    ctx = Context()
    h = ctx.add_host("10.0.0.7")
    h.services.append(Service(host="10.0.0.7", port=389, name="ldap"))
    h.services.append(Service(host="10.0.0.7", port=88, name="kerberos"))
    assert AdEnum().should_run(ctx) is True
    assert AdEnum().should_run(_ctx_web()) is False


def test_winrm_enum_triggers_on_windows_remote_management():
    ctx = Context()
    h = ctx.add_host("10.0.0.8")
    h.services.append(Service(host="10.0.0.8", port=5985, name="wsman"))
    h.services.append(Service(host="10.0.0.8", port=3389, name="ms-wbt-server"))
    assert WinRmEnum().should_run(ctx) is True
    assert WinRmEnum().should_run(_ctx_web()) is False


def test_identity_enum_triggers_on_admin_surface():
    ctx = Context()
    h = ctx.add_host("10.0.0.9")
    h.services.append(Service(host="10.0.0.9", port=445, name="microsoft-ds"))
    h.services.append(Service(host="10.0.0.9", port=389, name="ldap"))
    h.services.append(Service(host="10.0.0.9", port=5985, name="wsman"))
    assert IdentityEnum().should_run(ctx) is True
    assert IdentityEnum().should_run(_ctx_web()) is False


def test_privilege_path_triggers_on_ad_admin_surface():
    ctx = Context()
    h = ctx.add_host("10.0.0.10")
    h.services.append(Service(host="10.0.0.10", port=88, name="kerberos"))
    h.services.append(Service(host="10.0.0.10", port=389, name="ldap"))
    h.services.append(Service(host="10.0.0.10", port=445, name="microsoft-ds"))
    h.services.append(Service(host="10.0.0.10", port=5985, name="wsman"))
    assert PrivilegePath().should_run(ctx) is True
    assert PrivilegePath().should_run(_ctx_web()) is False


def test_osint_triage_extracts_indicators_from_local_artifact(tmp_path):
    artifact = tmp_path / "clue.txt"
    artifact.write_text("Contact admin@ctf.example and visit https://portal.ctf.example/path", encoding="utf-8")
    module = OsintTriage([str(artifact)])
    ctx = Context()

    assert module.should_run(ctx) is True
    module.run(ctx, None)

    finding = next(f for f in ctx.findings if f.source_module == module.name)
    assert "admin@ctf.example" in finding.evidence
    assert "portal.ctf.example" in finding.evidence


def test_crypto_triage_decodes_a_base64_ctf_flag(tmp_path):
    artifact = tmp_path / "encoded.txt"
    artifact.write_text("ZmxhZ3t0ZXN0X2N0Zl9kZWNvZGV9", encoding="ascii")
    module = CryptoTriage([str(artifact)])
    ctx = Context()

    assert module.should_run(ctx) is True
    module.run(ctx, None)

    finding = next(f for f in ctx.findings if f.source_module == module.name)
    assert "flag{test_ctf_decode}" in finding.evidence


def test_crypto_triage_uses_custom_flag_prefix(tmp_path):
    artifact = tmp_path / "encoded.txt"
    artifact.write_text("SFRCe2N0Zl9wcmVmaXh9", encoding="ascii")
    module = CryptoTriage([str(artifact)], flag_prefix="HTB{")
    ctx = Context()
    module.run(ctx, None)
    finding = next(f for f in ctx.findings if f.source_module == module.name)
    assert "HTB{ctf_prefix}" in finding.evidence


def test_osint_triage_finds_flag_in_local_artifact(tmp_path):
    artifact = tmp_path / "clue.txt"
    artifact.write_text("Nothing obvious. HTB{hidden_in_metadata}", encoding="utf-8")
    module = OsintTriage([str(artifact)], flag_prefix="HTB{")
    ctx = Context()
    module.run(ctx, None)
    finding = next(f for f in ctx.findings if f.source_module == module.name)
    assert "HTB{hidden_in_metadata}" in finding.evidence


def test_web_ctf_scans_custom_flag_prefix():
    module = WebCtf(flag_prefix="HTB{")
    ctx = Context()
    module._scan_page(ctx, "lab.local", "http://lab.local/", {}, "<p>HTB{web_flag}</p>")
    finding = next(f for f in ctx.findings if f.source_module == module.name)
    assert "HTB{web_flag}" in finding.evidence


def test_web_ctf_ignores_css_and_javascript_flag_shaped_code():
    module = WebCtf()
    ctx = Context()
    body = """
    <style>
      .loader{position:fixed}
      ul{padding:0}
      footer{margin-bottom:30px}
      .flag{display:inline;vertical-align:middle}
    </style>
    <script>try{if(sessionStorage.getItem('x')){}}</script>
    <p>Page normale</p>
    """

    module._scan_page(ctx, "lab.local", "http://lab.local/", {"Content-Type": "text/html"}, body)

    assert not any(f.source_module == module.name for f in ctx.findings)


def test_web_ctf_records_visible_flag_as_info_not_vulnerability():
    module = WebCtf()
    ctx = Context()
    module._scan_page(ctx, "lab.local", "http://lab.local/", {}, "<p>flag{valid_ctf_flag_123}</p>")

    findings = [f for f in ctx.findings if f.source_module == module.name]
    assert len(findings) == 1
    assert "flag{valid_ctf_flag_123}" in findings[0].evidence
    assert findings[0].severity == "info"


def test_main_pipeline_does_not_register_ctf_modules():
    modules = build_modules(None, "rapport.md", "quiet", allow_exploit=False)
    names = {module.name for module in modules}
    assert not any(name.startswith("ctf-") or name == "web-ctf" for name in names)


def test_reverse_triage_identifies_elf_and_flag_without_execution(tmp_path):
    artifact = tmp_path / "challenge.bin"
    elf_header = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + bytes.fromhex("3e00") + bytes(50)
    artifact.write_bytes(elf_header + b"\x00flag{static_reverse}\x00")
    module = ReverseTriage([str(artifact)])
    ctx = Context()

    assert module.should_run(ctx) is True
    module.run(ctx, None)

    finding = next(f for f in ctx.findings if f.source_module == module.name)
    assert "ELF" in finding.detail
    assert "flag{static_reverse}" in finding.evidence


def test_forensics_triage_identifies_pcap_and_embedded_flag(tmp_path):
    artifact = tmp_path / "capture.pcap"
    artifact.write_bytes(b"\xd4\xc3\xb2\xa1" + bytes(20) + b"flag{pcap_artifact}")
    module = ForensicsTriage([str(artifact)])
    ctx = Context()

    assert module.should_run(ctx) is True
    module.run(ctx, None)

    finding = next(f for f in ctx.findings if f.source_module == module.name)
    assert "PCAP" in finding.detail
    assert "flag{pcap_artifact}" in finding.evidence


def test_html_report_generated(tmp_path):
    ctx = _ctx_web()
    ctx.add_finding(Finding(host="10.0.0.5", title="Test", severity="high", remediation="Fix."))
    out = generate_html(ctx, tmp_path / "r.html", stealth_name="ghost")
    text = out.read_text(encoding="utf-8")
    assert "<html" in text and "Red Team" in text and "badge" in text


def test_pdf_report_generated(tmp_path):
    ctx = _ctx_web()
    ctx.add_finding(Finding(host="10.0.0.5", title="Test accentué é à —", severity="critical"))
    out = generate_pdf(ctx, tmp_path / "r.pdf", stealth_name="ghost")
    # fpdf2 est installé dans l'env de test : le PDF doit exister et commencer par %PDF
    assert out is not None
    assert out.read_bytes()[:4] == b"%PDF"
