"""
attack.py — Mapping MITRE ATT&CK.

Chaque action du bot est rattachée à une technique ATT&CK. C'est le langage des
pros : un rapport qui cite "T1046 - Network Service Discovery" plutôt que
"j'ai scanné les ports" montre que tu structures ta démarche comme un vrai
red teamer. Le prof qui a 20 ans de métier parle ce langage — autant le tenir.

Référence : https://attack.mitre.org/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str        # ex: "T1046"
    name: str      # ex: "Network Service Discovery"
    tactic: str    # ex: "Discovery"


# Registre des techniques utilisées par les modules du framework.
TECHNIQUES: dict[str, Technique] = {
    "T1595": Technique("T1595", "Active Scanning", "Reconnaissance"),
    "T1595.002": Technique("T1595.002", "Vulnerability Scanning", "Reconnaissance"),
    "T1046": Technique("T1046", "Network Service Discovery", "Discovery"),
    "T1592": Technique("T1592", "Gather Victim Host Information", "Reconnaissance"),
    "T1190": Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "T1110": Technique("T1110", "Brute Force", "Credential Access"),
    "T1110.001": Technique("T1110.001", "Password Guessing", "Credential Access"),
    "T1078": Technique("T1078", "Valid Accounts", "Initial Access"),
    "T1083": Technique("T1083", "File and Directory Discovery", "Discovery"),
    "T1135": Technique("T1135", "Network Share Discovery", "Discovery"),
    "T1087": Technique("T1087", "Account Discovery", "Discovery"),
    "T1018": Technique("T1018", "Remote System Discovery", "Discovery"),
}


def describe(tech_id: str) -> str:
    """Renvoie 'T1046 — Network Service Discovery (Discovery)' pour le rapport."""
    t = TECHNIQUES.get(tech_id)
    if not t:
        return tech_id
    return f"{t.id} — {t.name} ({t.tactic})"
