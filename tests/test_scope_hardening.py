"""
test_scope_hardening.py — Durcissement du scope gate (item 2).

Prouve : application du port ET du protocole à chaque action, blocage des
schémas d'URL dangereux, refus des redirections hors périmètre, protection
anti-DNS-rebinding / anti-SSRF (résolution contrôlée), exclusions explicites,
et absence d'extension implicite du périmètre. Les résolutions DNS sont
injectées (aucun accès réseau réel dans les tests).
"""

from __future__ import annotations

import email.message
import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core.scope import (
    Scope,
    ScopeViolation,
    _ScopedRedirectHandler,
    guard,
)
from modules.recon_nmap import NmapRecon
from modules.web_ctf import WebCtf


def lab() -> Scope:
    return Scope(
        hosts={"lab.local"},
        networks=[ipaddress.ip_network("192.168.56.0/24")],
        allowed_ports={80, 443},
    )


# --- Ports & protocoles (le trou corrigé) ---------------------------------- #
def test_port_enforced_per_action():
    s = lab()
    assert s.is_authorized("192.168.56.10", port=80) is True
    assert s.is_authorized("192.168.56.10", port=22) is False
    with pytest.raises(ScopeViolation):
        guard(s, "192.168.56.10", port=22)      # port hors scope -> refus


def test_nmap_command_uses_only_scope_allowed_ports():
    scanner = NmapRecon()
    scope = Scope(networks=[ipaddress.ip_network("192.0.2.0/24")], allowed_ports={80, 443})
    command = scanner._scan_command("192.0.2.10", scope)
    assert command[command.index("-p") + 1] == "80,443"
    assert "--top-ports" not in command


def test_protocol_enforced():
    s = Scope(networks=[ipaddress.ip_network("192.168.56.0/24")], allowed_protocols={"tcp"})
    assert s.is_authorized("192.168.56.10", port=80, proto="tcp") is True
    with pytest.raises(ScopeViolation):
        s.authorize("192.168.56.10", port=80, proto="udp")


# --- URL & schémas dangereux ----------------------------------------------- #
def test_dangerous_url_schemes_blocked():
    s = lab()
    assert s.authorize_url("http://192.168.56.10/", resolve=False) is True
    for bad in ("file:///etc/passwd", "gopher://192.168.56.10/", "ftp://192.168.56.10/"):
        with pytest.raises(ScopeViolation):
            s.authorize_url(bad, resolve=False)


# --- Redirections hors périmètre ------------------------------------------- #
def test_redirect_out_of_scope_refused():
    s = lab()
    handler = _ScopedRedirectHandler(s)
    # redirection vers une destination hors scope -> refus
    with pytest.raises(Exception):
        handler.redirect_request(
            req=None, fp=None, code=302, msg="Found",
            headers=email.message.Message(), newurl="http://evil.example/",
        )


def test_validate_redirect_in_scope_ok():
    s = lab()
    assert s.validate_redirect("https://192.168.56.10/app", resolve=False) is True


def test_web_ctf_does_not_follow_redirect_outside_scope():
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://192.0.2.1/flag")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scope = Scope(networks=[ipaddress.ip_network("127.0.0.1/32")])
        status, _, _ = WebCtf()._get(scope, f"http://127.0.0.1:{server.server_port}/")
        assert status == 302
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


# --- Anti-DNS-rebinding / anti-SSRF ---------------------------------------- #
def test_hostname_resolving_out_of_scope_is_refused():
    s = lab()
    s.resolver = lambda h: ["8.8.8.8"]          # lab.local "résout" hors réseau autorisé
    with pytest.raises(ScopeViolation):
        s.authorize("lab.local")


def test_hostname_resolving_in_scope_ok():
    s = lab()
    s.resolver = lambda h: ["192.168.56.10"]
    assert s.authorize("lab.local", port=443) is True


def test_metadata_and_loopback_are_blocked():
    # Programme web public (pas de réseau défini) : nom autorisé mais résolution
    # vers metadata/loopback/privé = refus (rebinding).
    s = Scope(hosts={"app.public"}, allowed_ports={443})
    for bad in ("169.254.169.254", "127.0.0.1", "10.0.0.5"):
        s.resolver = lambda h, _b=bad: [_b]
        with pytest.raises(ScopeViolation):
            s.authorize("app.public", port=443)
    s.resolver = lambda h: ["93.184.216.34"]   # IP publique routable -> OK
    assert s.authorize("app.public", port=443) is True


# --- Exclusions explicites -------------------------------------------------- #
def test_explicit_exclusion_wins_over_allowed_network():
    s = Scope(
        networks=[ipaddress.ip_network("192.168.56.0/24")],
        excluded_networks=[ipaddress.ip_network("192.168.56.5/32")],
        allowed_ports={80},
    )
    assert s.is_authorized("192.168.56.10", port=80) is True
    assert s.is_authorized("192.168.56.5", port=80) is False
    assert s.is_in_scope("192.168.56.5") is False


# --- Pas d'extension implicite --------------------------------------------- #
def test_discovered_subdomain_is_not_auto_in_scope():
    s = lab()
    assert s.is_in_scope("lab.local") is True
    assert s.is_in_scope("admin.lab.local") is False     # sous-domaine découvert -> hors scope
    with pytest.raises(ScopeViolation):
        s.authorize("admin.lab.local", resolve=False)


# --- Rétrocompatibilité de l'API historique -------------------------------- #
def test_backward_compatible_guard_and_checks():
    s = lab()
    guard(s, "192.168.56.10")                 # 2 args, comme avant : ne lève pas
    with pytest.raises(ScopeViolation):
        guard(s, "8.8.8.8")
    assert s.is_port_allowed(80) is True
    assert s.is_port_allowed(22) is False
    assert s.allow_dos is False
