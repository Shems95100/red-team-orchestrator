"""Tests des profils de furtivité."""

from core.stealth import get_profile, PROFILES


def test_ghost_is_slowest():
    ghost = get_profile("ghost")
    normal = get_profile("normal")
    # ghost doit avoir un timing nmap plus bas (plus furtif) que normal
    assert ghost.nmap_timing < normal.nmap_timing
    # et scanner moins de ports
    assert ghost.top_ports <= normal.top_ports


def test_ghost_adds_scan_delay():
    args = get_profile("ghost").nmap_args()
    assert "--scan-delay" in args
    assert "-T1" in args
    assert get_profile("ghost").top_ports <= 50
    assert get_profile("ghost").base_delay >= 4.0


def test_unknown_profile_falls_back_to_ghost():
    assert get_profile("inexistant").name == "ghost"


def test_all_profiles_have_valid_timing():
    for p in PROFILES.values():
        assert 0 <= p.nmap_timing <= 5
