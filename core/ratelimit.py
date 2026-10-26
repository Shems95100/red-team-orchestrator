"""
ratelimit.py — Limitation de débit PAR HÔTE (item 8).

Un outil sérieux ne martèle pas une cible : il espace ses requêtes vers un même
hôte d'un intervalle minimal. Ça protège l'infra de la cible (on reste un
testeur correct), ça réduit le bruit, et ça évite de se faire bloquer.

Thread-safe et simple : un dernier-horodatage par hôte + un verrou.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Garantit au moins `min_interval` secondes entre deux actions vers un hôte."""

    def __init__(self, min_interval: float = 0.5):
        self.min_interval = max(0.0, float(min_interval))
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        """Bloque si nécessaire pour respecter l'intervalle minimal pour cet hôte."""
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            last = self._last.get(host)
            if last is not None:
                delta = now - last
                if delta < self.min_interval:
                    time.sleep(self.min_interval - delta)
            # On ré-horodate APRÈS l'attente éventuelle.
            self._last[host] = time.monotonic()
