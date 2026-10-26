"""
context.py — L'état partagé de la mission.

Toutes les phases écrivent et lisent dans le même Context : la recon ajoute des
hôtes et des services, le matching CVE ajoute des findings, l'exploitation marque
ce qui a réussi. C'est ce qui permet au moteur de DÉCIDER la suite en fonction de
ce qui a déjà été découvert (au lieu de tirer à l'aveugle).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Logger du framework. Sans configuration (usage en bibliothèque / tests), les
# messages INFO restent silencieux ; main.py le configure pour la CLI.
_log = logging.getLogger("rto")


@dataclass
class Service:
    host: str
    port: int
    proto: str = "tcp"
    name: str = ""          # ex: "http", "ssh", "ftp"
    product: str = ""       # ex: "Apache httpd"
    version: str = ""       # ex: "2.4.49"
    banner: str = ""
    criticality: str = "medium"  # low | medium | high | critical

    def key(self) -> str:
        return f"{self.host}:{self.port}/{self.proto}"

    def importance_score(self) -> int:
        weights = {"low": 2, "medium": 5, "high": 12, "critical": 24}
        return weights.get(self.criticality.lower(), 5)


@dataclass
class Finding:
    host: str
    title: str
    severity: str = "info"   # info | low | medium | high | critical
    detail: str = ""
    evidence: str = ""
    source_module: str = ""
    cve: str = ""
    # Techniques MITRE ATT&CK associées (IDs du registre core.attack)
    attack_refs: list[str] = field(default_factory=list)
    # Reco de remédiation spécifique à ce finding (pour le rapport pro)
    remediation: str = ""
    # Niveau de confiance de la détection : "confirmed" | "firm" | "tentative" | "scanner"
    # (item 7 : chaque finding doit porter son niveau de confiance)
    confidence: str = "tentative"
    # Étapes de reproduction (item 7 : un finding sérieux est reproductible)
    steps: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Host:
    address: str
    hostname: str = ""
    os_guess: str = ""
    services: list[Service] = field(default_factory=list)


@dataclass
class Context:
    """État global transmis à toutes les phases."""

    hosts: dict[str, Host] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    # Journal horodaté de toute la kill chain — c'est ton futur rapport.
    timeline: list[dict] = field(default_factory=list)

    def add_host(self, address: str, **kw) -> Host:
        host = self.hosts.get(address)
        if host is None:
            host = Host(address=address, **kw)
            self.hosts[address] = host
        return host

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.log(finding.source_module, f"[{finding.severity.upper()}] {finding.title} sur {finding.host}")

    def log(self, module: str, message: str) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "module": module,
            "message": message,
        }
        self.timeline.append(entry)
        # Passe par logging : même rendu à l'écran, mais niveau/format/fichier
        # configurables, et capturable dans les tests.
        _log.info("  [%s] %s", module, message)

    def all_services(self) -> list[Service]:
        return [svc for host in self.hosts.values() for svc in host.services]

    def host_priority(self, host: str) -> int:
        """Score de priorité de la cible pour l'ordre d'exécution.

        Plus le score est élevé, plus la cible mérite une attention immédiate.
        Le calcul tient compte de la gravité du finding, de la confiance, du
        niveau de criticité des services exposés et du risque métier.
        """
        severity_weights = {"info": 5, "low": 12, "medium": 25, "high": 55, "critical": 95}
        confidence_weights = {"tentative": 1, "scanner": 2, "firm": 3, "confirmed": 5}
        score = 0

        for finding in self.findings:
            if finding.host != host:
                continue
            score += severity_weights.get(finding.severity.lower(), 0)
            score += confidence_weights.get((finding.confidence or "tentative").lower(), 1) * 8
            if finding.cve:
                score += 12
            if "database" in (finding.title + " " + finding.detail + " " + finding.evidence).lower():
                score += 20

        host_obj = self.hosts.get(host)
        if host_obj:
            score += sum(service.importance_score() for service in host_obj.services)
            score += min(len(host_obj.services) * 6, 24)
        return score

    def prioritized_hosts(self) -> list[str]:
        """Trie les hôtes par priorité décroissante."""
        return sorted(self.hosts.keys(), key=lambda h: self.host_priority(h), reverse=True)
