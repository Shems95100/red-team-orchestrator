"""
stealth.py — Profils de furtivité (réduction d'empreinte).

La discrétion ici = faire LE MOINS de bruit possible : moins de paquets, plus
lentement, de façon plus ciblée, pour passer sous les seuils de détection de la
blue team. C'est de la furtivité "low-and-slow", la plus solide et la plus
défendable à l'oral.

Ce fichier NE contient PAS d'anti-forensique / effacement de traces : dans un
exercice red vs blue, la blue team doit pouvoir analyser ce qui s'est passé.
La furtivité, c'est éviter l'alerte — pas détruire la capacité de détection.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass


@dataclass
class StealthProfile:
    name: str
    # Modèle de timing nmap (0=paranoid .. 5=insane). On reste bas pour la furtivité.
    nmap_timing: int
    # Nombre de ports scannés (top-N). Moins = plus discret.
    top_ports: int
    # Intensité de détection de version nmap (0..9). Bas = moins de sondes.
    version_intensity: int
    # Délai de base entre actions réseau (secondes) + jitter aléatoire ±.
    base_delay: float
    jitter: float
    # Nombre max de tentatives réseau (retries). Bas = moins de paquets.
    max_retries: int

    def sleep(self) -> None:
        """Pause furtive avec jitter — casse la régularité qui déclenche les alertes."""
        delay = self.base_delay + random.uniform(-self.jitter, self.jitter)
        if delay > 0:
            time.sleep(delay)

    def nmap_args(self) -> list[str]:
        """Traduit le profil en options nmap de réduction d'empreinte."""
        args = [
            f"-T{self.nmap_timing}",
            "-Pn",                       # pas de ping sweep bruyant
            "--top-ports", str(self.top_ports),
            "--version-intensity", str(self.version_intensity),
            "--max-retries", str(self.max_retries),
        ]
        # En mode très furtif, on étale encore plus les sondes.
        if self.nmap_timing <= 1:
            args += ["--scan-delay", "750ms", "--max-rate", "50"]
        elif self.nmap_timing == 2:
            args += ["--max-rate", "150"]
        return args


# Presets prêts à l'emploi.
PROFILES: dict[str, StealthProfile] = {
    # "ghost" : le plus discret. Très lent, ultra ciblé, image de marque du bot fantôme.
    # Les paquets sont limités, espacés et synthétisés pour rester en dessous des seuils de détection.
    "ghost": StealthProfile(
        name="ghost", nmap_timing=1, top_ports=25, version_intensity=1,
        base_delay=5.0, jitter=3.0, max_retries=1,
    ),
    # "quiet" : discret mais un peu plus rapide. Bon compromis.
    "quiet": StealthProfile(
        name="quiet", nmap_timing=2, top_ports=200, version_intensity=3,
        base_delay=2.0, jitter=1.2, max_retries=2,
    ),
    # "normal" : rythme standard, pas furtif. Pour tester vite en lab.
    "normal": StealthProfile(
        name="normal", nmap_timing=4, top_ports=1000, version_intensity=7,
        base_delay=0.0, jitter=0.0, max_retries=2,
    ),
}


def get_profile(name: str) -> StealthProfile:
    return PROFILES.get(name, PROFILES["ghost"])
