"""
scope.py — Le "scope gate" du framework (version durcie).

C'est LA pièce centrale d'un outil de pentest professionnel : AUCUNE action
n'est lancée contre une cible qui n'est pas explicitement autorisée. C'est ce
qui distingue un outil de pentest d'un malware, et le premier point à défendre
à l'oral.

Ce durcissement (item 2 du cahier des charges) corrige un vrai trou de la
version initiale : `guard()` ne vérifiait que l'hôte/réseau, jamais le PORT ni
le PROTOCOLE — donc `allowed_ports` du scope.yaml n'était pas réellement
appliqué. Il ajoute aussi, car une frontière réseau sérieuse en a besoin :

  - l'application du périmètre à CHAQUE action (hôte + port + protocole) ;
  - la validation des URL et des REDIRECTIONS HTTP (une 302 ne doit pas faire
    sortir du périmètre) ;
  - la vérification de la RÉSOLUTION DNS (anti-DNS-rebinding / anti-SSRF : un nom
    autorisé qui résout vers une IP interne, loopback ou 169.254.169.254 est
    refusé) ;
  - des EXCLUSIONS explicites (hôtes/réseaux interdits même s'ils tombent dans
    une plage autorisée) ;
  - l'absence d'extension implicite : un sous-domaine, une redirection ou une
    cible secondaire découverte n'élargit JAMAIS le périmètre.

Rétrocompatibilité : l'API existante (`is_in_scope`, `is_port_allowed`,
`guard(scope, cible)`, `allow_dos`) est conservée. Les quotas de requêtes et
délais, eux, relèvent du budget d'orchestration (voir core.investigation.Budget).
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

import yaml


# Type d'un résolveur DNS injectable (facilite les tests sans réseau).
Resolver = Callable[[str], list[str]]


def _default_resolver(host: str) -> list[str]:
    """Résout un nom en liste d'IP (toutes familles). Lève sur échec (fail-closed)."""
    infos = socket.getaddrinfo(host, None)
    out: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


class ScopeViolation(Exception):
    """Levée quand une action tente de sortir du périmètre autorisé."""


@dataclass
class Scope:
    """Périmètre autorisé pour la mission."""

    # Noms d'hôtes / domaines autorisés (correspondance EXACTE, insensible à la casse)
    hosts: set[str] = field(default_factory=set)
    # Réseaux autorisés : objets ip_network (accepte IP seule ou CIDR)
    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    # Ports autorisés ; vide = tous les ports
    allowed_ports: set[int] = field(default_factory=set)

    # --- Nouveaux garde-fous (tous optionnels, défauts sûrs) --------------- #
    # Exclusions explicites : prioritaires sur les autorisations.
    excluded_hosts: set[str] = field(default_factory=set)
    excluded_networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    # Protocoles autorisés (ex. {"tcp"}) ; vide = tous.
    allowed_protocols: set[str] = field(default_factory=set)
    # Schémas d'URL autorisés (bloque file://, gopher://… vecteurs SSRF classiques).
    allowed_schemes: set[str] = field(default_factory=lambda: {"http", "https"})
    # Vérifier que la résolution DNS d'un nom reste dans le périmètre (anti-rebinding).
    enforce_resolved_scope: bool = True
    # DoS / flood : interdit par défaut, et on le laisse interdit.
    allow_dos: bool = False
    # Résolveur injectable (défaut : DNS système). Mis à part pour les tests.
    resolver: Optional[Resolver] = None

    # ------------------------------------------------------------------ #
    # Chargement
    # ------------------------------------------------------------------ #
    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}

        def _nets(key: str) -> list[ipaddress._BaseNetwork]:
            return [ipaddress.ip_network(str(e).strip(), strict=False)
                    for e in data.get(key, []) if str(e).strip()]

        return cls(
            hosts={h.strip().lower() for h in data.get("hosts", []) if str(h).strip()},
            networks=_nets("networks"),
            allowed_ports={int(p) for p in data.get("allowed_ports", [])},
            excluded_hosts={h.strip().lower() for h in data.get("excluded_hosts", []) if str(h).strip()},
            excluded_networks=_nets("excluded_networks"),
            allowed_protocols={str(p).strip().lower() for p in data.get("allowed_protocols", [])},
            allowed_schemes={str(s).strip().lower() for s in data.get("allowed_schemes", ["http", "https"])},
            enforce_resolved_scope=bool(data.get("enforce_resolved_scope", True)),
            allow_dos=bool(data.get("allow_dos", False)),
        )

    # ------------------------------------------------------------------ #
    # API historique (conservée)
    # ------------------------------------------------------------------ #
    def is_in_scope(self, target: str) -> bool:
        """Appartenance SPATIALE au périmètre (hôte/réseau), sans résolution DNS.

        Sert au pré-filtrage rapide des cibles. La décision complète par action
        (port, protocole, DNS, redirections) passe par `authorize()`.
        """
        target = target.strip().lower()
        try:
            addr = ipaddress.ip_address(target)
            if self._ip_excluded(addr):
                return False
            return self._ip_in_networks(addr)
        except ValueError:
            pass
        if target in self.excluded_hosts:
            return False
        return target in self.hosts

    def is_port_allowed(self, port: int) -> bool:
        return not self.allowed_ports or port in self.allowed_ports

    # ------------------------------------------------------------------ #
    # Décision par action (hôte + port + protocole + DNS)
    # ------------------------------------------------------------------ #
    def deny_reason(
        self,
        target: str,
        port: Optional[int] = None,
        proto: str = "tcp",
        *,
        resolve: Optional[bool] = None,
    ) -> Optional[str]:
        """Renvoie la raison du refus, ou None si l'action est autorisée."""
        target = target.strip().lower()
        proto = proto.strip().lower()

        if self.allowed_protocols and proto not in self.allowed_protocols:
            return f"protocole '{proto}' non autorisé"
        if port is not None and not self.is_port_allowed(port):
            return f"port {port} hors périmètre (allowed_ports={sorted(self.allowed_ports)})"

        # Cible = IP littérale -> on fait confiance au périmètre réseau explicite.
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            addr = None

        if addr is not None:
            if self._ip_excluded(addr):
                return f"IP explicitement exclue : {target}"
            if not self._ip_in_networks(addr):
                return f"IP hors des réseaux autorisés : {target}"
            return None

        # Cible = nom d'hôte -> correspondance exacte + contrôle de résolution.
        if target in self.excluded_hosts:
            return f"hôte explicitement exclu : {target}"
        if target not in self.hosts:
            return f"hôte hors périmètre : {target} (pas d'extension implicite)"

        do_resolve = self.enforce_resolved_scope if resolve is None else resolve
        if do_resolve:
            resolver = self.resolver or _default_resolver
            try:
                ips = resolver(target)
            except Exception as e:  # noqa: BLE001 — DNS KO = refus (fail-closed)
                return f"résolution DNS impossible pour {target} ({e!r}) — refus par sécurité"
            if not ips:
                return f"aucune IP résolue pour {target}"
            for ip in ips:
                try:
                    raddr = ipaddress.ip_address(ip)
                except ValueError:
                    return f"résolution DNS invalide pour {target} -> {ip!r}"
                why = self._resolved_ip_reason(raddr)
                if why:
                    return f"{why} : {target} -> {ip}"
        return None

    def authorize(
        self,
        target: str,
        port: Optional[int] = None,
        proto: str = "tcp",
        *,
        resolve: Optional[bool] = None,
    ) -> bool:
        """Autorise l'action ou lève ScopeViolation avec un motif explicite."""
        reason = self.deny_reason(target, port, proto, resolve=resolve)
        if reason:
            raise ScopeViolation(reason)
        return True

    def is_authorized(self, target: str, port: Optional[int] = None, proto: str = "tcp") -> bool:
        return self.deny_reason(target, port, proto) is None

    # ------------------------------------------------------------------ #
    # URL & redirections
    # ------------------------------------------------------------------ #
    def authorize_url(self, url: str, *, resolve: Optional[bool] = None) -> bool:
        """Autorise une URL complète (schéma + hôte + port). Lève sinon."""
        p = urlparse(url)
        scheme = (p.scheme or "").lower()
        if self.allowed_schemes and scheme not in self.allowed_schemes:
            raise ScopeViolation(f"schéma '{scheme or '∅'}' non autorisé (anti-SSRF) : {url}")
        host = p.hostname
        if not host:
            raise ScopeViolation(f"URL sans hôte : {url}")
        port = p.port or (443 if scheme == "https" else 80)
        return self.authorize(host, port=port, proto="tcp", resolve=resolve)

    def validate_redirect(self, to_url: str, *, resolve: Optional[bool] = None) -> bool:
        """À appeler AVANT de suivre une redirection : refuse une 3xx hors périmètre."""
        return self.authorize_url(to_url, resolve=resolve)

    # ------------------------------------------------------------------ #
    # Helpers internes
    # ------------------------------------------------------------------ #
    def _ip_in_networks(self, addr: ipaddress._BaseAddress) -> bool:
        return any(addr in net for net in self.networks)

    def _ip_excluded(self, addr: ipaddress._BaseAddress) -> bool:
        return any(addr in net for net in self.excluded_networks)

    def _resolved_ip_reason(self, addr: ipaddress._BaseAddress) -> Optional[str]:
        """Motif de refus d'une IP RÉSOLUE (anti-rebinding), ou None si OK."""
        if self._ip_excluded(addr):
            return "IP résolue exclue"
        # Jamais de cible interne/non routable via un nom (metadata, loopback…).
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            return "IP résolue interne/non routable (anti-rebinding / anti-SSRF)"
        if self.networks:
            if not self._ip_in_networks(addr):
                return "IP résolue hors des réseaux autorisés (rebinding ?)"
        else:
            # Pas de réseau défini (programme web public) : on exige du routable public.
            if addr.is_private or addr.is_reserved:
                return "IP résolue privée/réservée hors périmètre (rebinding ?)"
        return None


# --------------------------------------------------------------------------- #
# Garde historique (conservée) + ouverture HTTP respectant le périmètre
# --------------------------------------------------------------------------- #
def guard(scope: Scope, target: str, port: Optional[int] = None, proto: str = "tcp") -> None:
    """Garde à appeler en tête de chaque action active.

    Rétrocompatible : `guard(scope, cible)` fonctionne comme avant. En
    précisant `port`/`proto`, la garde applique aussi le filtrage de ports et de
    protocoles — c'est la correction du trou "ports configurés ≠ ports scannés".
    """
    scope.authorize(target, port=port, proto=proto)


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse toute redirection HTTP dont la destination sort du périmètre."""

    def __init__(self, scope: Scope):
        self.scope = scope

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        try:
            self.scope.authorize_url(newurl)
        except ScopeViolation as e:
            raise urllib.error.HTTPError(
                newurl, code, f"redirection hors périmètre refusée : {e}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def make_scoped_opener(scope: Scope) -> urllib.request.OpenerDirector:
    """Construit un opener urllib qui bloque les redirections hors périmètre.

    Usage dans un module HTTP :
        opener = make_scoped_opener(scope)
        resp = opener.open(req, timeout=10)   # une 302 hors scope lève HTTPError
    """
    return urllib.request.build_opener(_ScopedRedirectHandler(scope))
