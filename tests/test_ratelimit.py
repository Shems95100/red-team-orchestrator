"""Test du rate-limiter par hôte (item 8)."""

import time

from core.ratelimit import RateLimiter


def test_spaces_requests_to_same_host():
    rl = RateLimiter(min_interval=0.2)
    start = time.monotonic()
    rl.wait("a")            # 1er appel : immédiat
    rl.wait("a")            # 2e : doit attendre ~0.2s
    rl.wait("a")            # 3e : encore ~0.2s
    elapsed = time.monotonic() - start
    assert elapsed >= 0.4 - 0.05   # au moins ~2 intervalles


def test_different_hosts_not_blocked_by_each_other():
    rl = RateLimiter(min_interval=0.5)
    start = time.monotonic()
    rl.wait("a")
    rl.wait("b")            # hôte différent : pas d'attente
    elapsed = time.monotonic() - start
    assert elapsed < 0.3


def test_zero_interval_never_waits():
    rl = RateLimiter(min_interval=0)
    start = time.monotonic()
    for _ in range(5):
        rl.wait("a")
    assert time.monotonic() - start < 0.1
