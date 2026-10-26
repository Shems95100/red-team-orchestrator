# Red Team Orchestrator

Framework modulaire d'orchestration **red team** pour environnements de **lab
autorisé** (exercices red team / blue team, CTF, labs pédagogiques). Le bot
découvre une cible, s'adapte à ce qu'il trouve, cherche les vulnérabilités
connues à jour, mène une investigation chaînée, et produit un rapport de mission
multi-format.

> ⚠️ **Usage strictement autorisé.** L'outil refuse toute cible absente du
> périmètre (`scope.yaml`). À n'utiliser que sur des machines et des réseaux
> pour lesquels tu as une autorisation écrite. Ce dépôt ne contient aucun
> périmètre réel ni aucun payload d'exploitation weaponisé.

## Idée directrice

Un bon bot red team ne lance pas des centaines d'exploits à l'aveugle — c'est
bruyant, ça casse les cibles et ça se fait repérer par la blue team. Celui-ci
fait l'inverse : **il découvre, puis il décide.** Chaque module ne se déclenche
que si l'état courant le justifie (`should_run`), et chaque *finding* devient une
hypothèse que le moteur d'investigation cherche à confirmer, dans la limite d'un
budget et du périmètre autorisé.

## Architecture

```
main.py                → point d'entrée CLI, enregistre les modules (build_modules)
gui.py                 → interface graphique Tkinter (lancer une mission sans la CLI)
core/
  scope.py             → scope gate durci : hôte + port + protocole + URL + DNS
  exploit_policy.py    → politique d'exploitation (autorisation, sévérité, preuve)
  stealth.py           → profils de furtivité (ghost / quiet / normal) + jitter
  attack.py            → registre MITRE ATT&CK (techniques)
  context.py           → état partagé de la mission (hôtes, services, findings)
  engine.py            → moteur : déroule les phases, lance les modules adaptatifs
  investigation.py     → moteur d'investigation chaînée (hypothèses → probes)
  ratelimit.py         → limitation de débit des requêtes
  reporting.py         → rapport Markdown + export JSON
  report_html.py       → rapport HTML
  report_pdf.py        → rapport PDF (via fpdf2)
modules/               → capacités par phase (recon, enum, vuln, exploit, post, report)
  recon_nmap.py, osint.py                         → recon
  enum_http.py, enum_smb.py, enum_ad.py,          → enum
  enum_winrm.py, enum_identity.py, web_ctf.py
  cve_lookup.py, audit_notice.py, ctf_*.py,       → vuln
  forensics_triage.py, reverse_triage.py,
  investigation_module.py
  exploit_web.py, exploit_ssh.py,                 → exploit (templates gardés)
  check_default_creds.py
  post_exploit.py, privilege_path.py              → post
  report_module.py                                → report
tests/                 → suite pytest (scope, furtivité, reporting, investigation…)
```

Phases déroulées dans l'ordre : `recon → enum → vuln → exploit → post → report`.

## Points de conception (ce qui distingue l'outil d'un simple scanner)

- **Scope gate durci.** Aucune action n'est lancée hors périmètre. Le contrôle
  s'applique à **chaque** action : hôte, port, protocole, schéma d'URL (anti-SSRF :
  `file://`, `gopher://` bloqués), redirections HTTP (une 302 ne fait pas sortir
  du scope) et résolution DNS (anti-DNS-rebinding : un nom autorisé qui résout
  vers une IP interne / loopback / metadata est refusé). Exclusions explicites,
  aucune extension implicite du périmètre. Résolveur DNS injectable pour les
  tests sans réseau.
- **Moteur adaptatif + investigation chaînée.** Les modules se déclenchent selon
  ce qui est découvert ; chaque finding devient une hypothèse à confirmer, avec
  profondeur de chaînage bornée et terminaison garantie (jamais de boucle).
- **Exploitation sous politique.** Les modules d'exploitation sont des *templates*
  désactivés par défaut, encadrés par `ExploitPolicy` (autorisation explicite,
  seuil de sévérité, mode dry-run). Pas de base d'exploits weaponisés en dur.
- **OPSEC mesurée.** Profils de furtivité + jitter anti-IDS + limitation de débit.
- **Méthodologie cadrée.** Phases PTES, actions mappées sur MITRE ATT&CK.
- **Qualité logicielle.** Architecture modulaire, séparation cerveau/mains,
  rapports Markdown / JSON / HTML / PDF, et une suite de tests fournie.

## Installation

```bash
pip install -r requirements.txt     # PyYAML, fpdf2 (PDF), pytest (dev)
# nmap requis pour la phase recon : apt install nmap  (ou équivalent)
```

## Utilisation

```bash
cp scope.example.yaml scope.yaml    # édite scope.yaml avec TES cibles autorisées
python main.py --scope scope.yaml --targets 192.168.56.101 --mode audit
```

Le mode `audit` (par défaut) désactive exploitation et post-exploitation. Options
utiles : `--targets-file`, `--nvd-key` (clé API NVD), `--stealth ghost|quiet|normal`,
`--report mon_rapport.md`. Interface graphique : `python gui.py`.

## Tests

```bash
pip install -r requirements.txt
python -m pytest -q
```

## Ce que l'outil ne fait pas (volontairement)

- **Pas de DoS / flood.** Faire tomber une cible n'est pas du pentest.
- **Pas d'anti-forensique.** Dans un exercice red vs blue, la blue team doit
  pouvoir analyser la mission ; la furtivité consiste à éviter l'alerte, pas à
  détruire la détection.
- **Pas de payloads d'exploitation prêts à l'emploi.** Les modules d'exploit
  s'adaptent au lab autorisé et doivent être complétés par l'opérateur.

---

Projet réalisé dans le cadre de ma formation en cybersécurité à la Guardia
Cybersecurity School (exercice Red Team vs Blue Team). Sous licence MIT.
