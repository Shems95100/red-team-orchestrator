"""
enum_http.py — Phase enum : énumération web (détection affinée, item 7).

Démontre le routage adaptatif : ce module ne se déclenche QUE si la recon a
trouvé un service web. Il fait de l'énumération passive/active légère :
  - fingerprint du serveur et des technos (en-têtes HTTP) ;
  - audit des en-têtes de sécurité manquants ;
  - sondage de quelques chemins sensibles classiques.

Amélioration qualité (item 7) : on NE considère PLUS qu'une réponse HTTP < 400
est une exposition. On VÉRIFIE le contenu par signature (un /.git/HEAD doit
vraiment ressembler à un HEAD git, un /.env à un fichier d'environnement, etc.),
on distingue accessible (200) / protégé (401-403), et chaque finding porte son
niveau de confiance et ses étapes de reproduction.

Tout est furtif (pacing + jitter), rate-limité par hôte et scope-guardé.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

from core.context import Context, Finding
from core.ratelimit import RateLimiter
from core.scope import Scope, guard
from core.stealth import StealthProfile, get_profile
from modules.base import Module

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
]

# Chemins sensibles + fonction de signature qui valide le CONTENU réellement reçu.
# (path, description, signature(body)->bool, severity_si_confirmé)
COMMON_PATHS = [
    ("robots.txt", "fichier robots.txt", lambda b: looks_like_robots(b), "info"),
    (".git/HEAD", "dépôt git exposé", lambda b: looks_like_git_head(b), "high"),
    (".env", "fichier d'environnement exposé", lambda b: looks_like_env(b), "high"),
    ("server-status", "page Apache server-status", lambda b: looks_like_server_status(b), "medium"),
    ("phpinfo.php", "page phpinfo()", lambda b: looks_like_phpinfo(b), "medium"),
]

AUDIT_PATHS = [
    ("robots.txt", "fichier robots.txt", lambda b: looks_like_robots(b), "info"),
    ("sitemap.xml", "plan du site", lambda b: "<urlset" in b.lower() or "<sitemapindex" in b.lower(), "info"),
    (".well-known/security.txt", "security.txt", lambda b: "contact:" in b.lower() or "policy:" in b.lower(), "info"),
]
PUBLIC_METADATA_PATHS = {"robots.txt", "sitemap.xml", ".well-known/security.txt"}


# --------------------------------------------------------------------------- #
# Signatures de contenu (fonctions PURES -> testables sans réseau)
# --------------------------------------------------------------------------- #
def _is_html(body: str) -> bool:
    low = body.lstrip()[:200].lower()
    return low.startswith("<!doctype html") or "<html" in low


def looks_like_git_head(body: str) -> bool:
    b = body.strip()
    # Un vrai .git/HEAD : "ref: refs/heads/..." ou un hash de 40 hex.
    return bool(re.match(r"^ref:\s+refs/", b)) or bool(re.fullmatch(r"[0-9a-f]{40}", b))


def looks_like_env(body: str) -> bool:
    if _is_html(body):
        return False
    # Au moins deux lignes CLE=VALEUR en MAJUSCULES (typique d'un .env).
    lines = [l for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]
    kv = [l for l in lines if re.match(r"^[A-Z][A-Z0-9_]*=", l.strip())]
    return len(kv) >= 2


def looks_like_server_status(body: str) -> bool:
    return "Apache Server Status" in body or "Server uptime" in body


def looks_like_phpinfo(body: str) -> bool:
    low = body.lower()
    return "phpinfo()" in low or "php version" in low and "<title>phpinfo" in low


def looks_like_robots(body: str) -> bool:
    low = body.lower()
    return ("user-agent:" in low or "disallow:" in low) and not _is_html(body)


class HttpEnum(Module):
    name = "http-enum"
    phase = "enum"
    attack_refs = ["T1595", "T1083"]  # Active Scanning + File/Directory Discovery

    def __init__(self, stealth: StealthProfile | None = None, rate: RateLimiter | None = None,
                 safe_mode: bool = False):
        self.stealth = stealth or get_profile("quiet")
        self.safe_mode = safe_mode
        self.paths = AUDIT_PATHS if safe_mode else COMMON_PATHS
        # Rate-limit par hôte (item 8) : on espace les requêtes vers un même hôte.
        self.rate = rate or RateLimiter(min_interval=0.4)

    def should_run(self, ctx: Context) -> bool:
        return any(
            svc.name in ("http", "https", "http-proxy") or svc.port in (80, 443, 8080, 8443)
            for svc in ctx.all_services()
        )

    def run(self, ctx: Context, scope: Scope) -> None:
        for svc in ctx.all_services():
            is_web = svc.name in ("http", "https", "http-proxy") or svc.port in (80, 443, 8080, 8443)
            if not is_web:
                continue
            guard(scope, svc.host)
            scheme = "https" if (svc.name == "https" or svc.port in (443, 8443)) else "http"
            base = f"{scheme}://{svc.host}:{svc.port}/"
            self._fingerprint(ctx, svc.host, base)
            self._check_paths(ctx, svc.host, base)

    def _fingerprint(self, ctx: Context, host: str, base: str) -> None:
        self.rate.wait(host)
        self.stealth.sleep()
        status, headers, _ = self._get(base, head=True)
        if headers is None:
            ctx.log(self.name, f"{base} injoignable — rien à signaler.")
            return
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        if server or powered:
            ctx.add_finding(Finding(
                host=host, title="Fingerprint serveur web",
                severity="info", confidence="firm",
                detail=f"Server: {server or 'n/a'} | X-Powered-By: {powered or 'n/a'}",
                evidence=base, source_module=self.name, attack_refs=["T1595"],
                steps=[f"curl -sI {base}"],
            ))
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        if missing:
            ctx.add_finding(Finding(
                host=host, title="En-têtes de sécurité manquants",
                severity="low", confidence="firm",
                detail="Manquants : " + ", ".join(missing),
                evidence=base, source_module=self.name,
                remediation="Ajouter les en-têtes de sécurité HTTP manquants (CSP, HSTS, "
                            "X-Frame-Options, X-Content-Type-Options).",
                steps=[f"curl -sI {base}", "Observer l'absence des en-têtes listés."],
            ))

    def _check_paths(self, ctx: Context, host: str, base: str) -> None:
        for path, desc, signature, sev in self.paths:
            self.rate.wait(host)
            self.stealth.sleep()
            url = base + path
            status, _, body = self._get(url)
            if status is None:
                continue

            # Protégé (401/403) : information utile, mais PAS une exposition.
            if status in (401, 403):
                ctx.add_finding(Finding(
                    host=host, title=f"/{path} présent mais protégé (HTTP {status})",
                    severity="info", confidence="firm",
                    detail=f"{desc} : le chemin existe mais nécessite une authentification.",
                    evidence=url, source_module=self.name, attack_refs=["T1083"],
                    steps=[f"curl -s -o /dev/null -w '%{{http_code}}' {url}"],
                ))
                continue

            if status >= 400:
                continue  # 404 etc. : rien.

            # 2xx/3xx : on VÉRIFIE le contenu avant de crier à l'exposition.
            body = body or ""
            if signature(body):
                if path in PUBLIC_METADATA_PATHS:
                    ctx.add_finding(Finding(
                        host=host, title=f"Fichier public standard détecté : /{path}",
                        severity="info", confidence="firm",
                        detail=f"{desc} est accessible comme prévu ; sa présence seule ne constitue pas une vulnérabilité.",
                        evidence=f"{url} (HTTP {status})",
                        source_module=self.name,
                        steps=[f"GET {url}"],
                    ))
                    continue
                ctx.add_finding(Finding(
                    host=host, title=f"Exposition confirmée : /{path}",
                    severity=sev, confidence="firm",
                    detail=f"{desc} — le contenu correspond à la signature attendue.",
                    evidence=f"{url} (HTTP {status}, signature validée)",
                    source_module=self.name, attack_refs=["T1083"],
                    remediation=f"Restreindre ou supprimer l'accès public à /{path}.",
                    steps=[f"curl -s {url}", "Vérifier que le contenu correspond bien au fichier sensible."],
                ))
            else:
                # Répond 200 mais le contenu ne colle pas : piste faible à vérifier à la main,
                # PAS un finding affirmatif (c'est ça, éviter le faux positif).
                ctx.add_finding(Finding(
                    host=host, title=f"/{path} répond 200 mais contenu non concluant",
                    severity="info", confidence="tentative",
                    detail=f"{desc} : réponse 200 mais la signature de contenu ne correspond pas "
                           f"(souvent une page d'accueil ou une redirection applicative).",
                    evidence=url, source_module=self.name,
                    steps=[f"curl -s {url}", "Inspecter la réponse manuellement."],
                ))

    # --- helper réseau unique -------------------------------------------- #
    def _get(self, url: str, head: bool = False):
        """Renvoie (status, headers_dict|None, body_str). Robuste aux erreurs réseau."""
        method = "HEAD" if head else "GET"
        req = urllib.request.Request(url, method=method, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = "" if head else resp.read(65536).decode("utf-8", "replace")
                return resp.status, {k: v for k, v in resp.headers.items()}, body
        except urllib.error.HTTPError as e:
            body = "" if head else (e.read(65536).decode("utf-8", "replace") if e.fp else "")
            hdrs = {k: v for k, v in e.headers.items()} if e.headers else {}
            return e.code, hdrs, body
        except Exception:  # noqa: BLE001 — injoignable / timeout / TLS
            return None, None, ""
