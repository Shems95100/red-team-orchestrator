"""
Tests du scope gate — la pièce critique de sécurité du framework.
Si ces tests passent, on a la garantie que le bot refuse toute cible hors scope.
"""

import pytest

from core.scope import Scope, ScopeViolation, guard


@pytest.fixture
def scope():
    return Scope(
        hosts={"lab.local"},
        networks=[__import__("ipaddress").ip_network("192.168.56.0/24")],
    )


def test_ip_in_network_is_in_scope(scope):
    assert scope.is_in_scope("192.168.56.42") is True


def test_ip_outside_network_is_out_of_scope(scope):
    assert scope.is_in_scope("8.8.8.8") is False


def test_known_hostname_is_in_scope(scope):
    assert scope.is_in_scope("lab.local") is True
    assert scope.is_in_scope("LAB.LOCAL") is True  # insensible à la casse


def test_unknown_hostname_is_out_of_scope(scope):
    assert scope.is_in_scope("google.com") is False


def test_guard_raises_on_out_of_scope(scope):
    with pytest.raises(ScopeViolation):
        guard(scope, "8.8.8.8")


def test_guard_passes_on_in_scope(scope):
    # Ne doit pas lever d'exception
    guard(scope, "192.168.56.10")


def test_dos_disabled_by_default(scope):
    assert scope.allow_dos is False


def test_port_filtering():
    s = Scope(hosts={"lab.local"}, allowed_ports={80, 443})
    assert s.is_port_allowed(80) is True
    assert s.is_port_allowed(22) is False
    # Liste vide = tous les ports autorisés
    assert Scope(hosts={"x"}).is_port_allowed(9999) is True
