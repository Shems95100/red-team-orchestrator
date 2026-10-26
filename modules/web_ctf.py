"""
web_ctf.py — Phase enum : chasse aux flags web (orienté CTF).

Pour la catégorie "web" d'un CTF : si un service web est dans le périmètre, ce
module va chercher les endroits où les auteurs de CTF cachent des flags et des
indices — commentaires HTML, robots.txt, cookies, en-têtes custom, fichiers
classiques (sitemap, .well-known), et toute chaîne au format flag.

C'est de la DÉCOUVERTE orientée CTF, non destructive, scope-guardée. Il ne tente
aucune exploitation : il lit des pages et signale ce qui ressemble à un flag ou
à une piste.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from html.parser import HTMLParser

from core.context import Context, Finding
from core.scope import Scope, guard, make_scoped_opener
from modules.base import Module
from modules.ctf_patterns import build_flag_pattern

FLAG_VALUE_RE = re.compile(r"[A-Za-z0-9_./+=-]{1,160}\Z")


class _PageContentParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.visible_text: list[str] = []
        self.comments: list[str] = []
        self._code_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"style", "script"}:
            self._code_depth += 1

    def handle_endtag(self, tag):
        if tag.lower() in {"style", "script"} and self._code_depth:
            self._code_depth -= 1

    def handle_data(self, data):
        if not self._code_depth:
            self.visible_text.append(data)

    def handle_comment(self, data):
        if not self._code_depth:
            self.comments.append(data)

# Chemins souvent porteurs d'indices en CTF web.
CTF_PATHS = [
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    "flag", "flag.txt", "secret", "admin", "backup", ".htaccess",
]
AUDIT_PATHS = ["robots.txt", "sitemap.xml", ".well-known/security.txt"]


class WebCtf(Module):
    name = "web-ctf"
    phase = "enum"
    attack_refs = ["T1083", "T1592"]

    def __init__(self, flag_prefix: str | None = None, safe_mode: bool = False):
        self.flag_re = build_flag_pattern(flag_prefix)
        self.safe_mode = safe_mode
        self.paths = AUDIT_PATHS if safe_mode else CTF_PATHS

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
            guard(scope, svc.host, port=svc.port)
            scheme = "https" if (svc.name == "https" or svc.port in (443, 8443)) else "http"
            base = f"{scheme}://{svc.host}:{svc.port}/"

            # 1) Page d'accueil : flags en clair, commentaires, cookies, en-têtes.
            status, headers, body = self._get(scope, base)
            if status is not None:
                self._scan_page(ctx, svc.host, base, headers, body)

            # 2) Chemins classiques de CTF.
            for path in self.paths:
                url = base + path
                st, hd, bd = self._get(scope, url)
                if st and st < 400 and bd:
                    self._scan_page(ctx, svc.host, url, hd, bd, path_hint=path)

    def _scan_page(self, ctx, host, url, headers, body, path_hint=None):
        body = body or ""
        headers = headers or {}
        parser = _PageContentParser()
        content_type = headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in {"text/css", "text/javascript", "application/javascript", "application/x-javascript"}:
            parser.feed(body)
            parser.close()

        for flag in self._find_flags(" ".join(parser.visible_text)):
            ctx.add_finding(Finding(
                host=host, title=f"Flag CTF détecté dans la réponse : {flag}",
                severity="info", confidence="firm",
                detail="Une chaîne au format flag apparaît dans le texte visible de la réponse.",
                evidence=f"{url} -> {flag}", source_module=self.name,
                steps=[f"Ouvrir {url}", "Vérifier le flag dans le contenu visible de la page."],
            ))

        for c in parser.comments:
            c = c.strip()
            if not c:
                continue
            flags = self._find_flags(c)
            if flags:
                ctx.add_finding(Finding(
                    host=host, title=f"Flag CTF dans un commentaire HTML : {flags[0]}",
                    severity="info", confidence="firm",
                    detail=f"Commentaire HTML contenant un flag : {c[:120]}", evidence=f"{url} -> {flags[0]}",
                    source_module=self.name,
                    steps=[f"Ouvrir le code source de {url}", "Vérifier le commentaire HTML."],
                ))
            elif any(k in c.lower() for k in ("todo", "password", "secret", "key", "admin", "flag")):
                ctx.add_finding(Finding(
                    host=host, title="Commentaire HTML potentiellement sensible",
                    severity="low", confidence="tentative",
                    detail=f"Commentaire : {c[:160]}", evidence=url,
                    source_module=self.name,
                    steps=[f"curl -s {url}", "Inspecter les commentaires HTML."],
                ))

        # Cookies et en-têtes custom (souvent des indices en CTF).
        cookie = headers.get("Set-Cookie", "")
        cookie_flags = self._find_flags(cookie)
        if cookie_flags:
            ctx.add_finding(Finding(
                host=host, title="Flag CTF détecté dans un cookie",
                severity="info", confidence="firm",
                detail="Un cookie contient une chaîne au format flag.", evidence=f"{url} -> {cookie_flags[0]}",
                source_module=self.name,
                steps=[f"Examiner le cookie renvoyé par {url} en environnement CTF."],
            ))
        for hname, hval in headers.items():
            header_flags = self._find_flags(str(hval))
            if hname.lower().startswith("x-") and header_flags:
                ctx.add_finding(Finding(
                    host=host, title=f"Flag CTF détecté dans l'en-tête {hname}",
                    severity="info", confidence="firm",
                    detail=f"L'en-tête {hname} contient une chaîne au format flag.",
                    evidence=f"{url} -> {header_flags[0]}", source_module=self.name,
                    steps=[f"Vérifier l'en-tête {hname} renvoyé par {url}."],
                ))

        # robots.txt : les Disallow pointent souvent vers des chemins cachés.
        if path_hint == "robots.txt":
            disallows = re.findall(r"(?i)Disallow:\s*(\S+)", body)
            if disallows:
                ctx.add_finding(Finding(
                    host=host, title=f"robots.txt expose {len(disallows)} chemin(s) caché(s)",
                    severity="info", confidence="firm",
                    detail="Chemins : " + ", ".join(disallows[:10]), evidence=url,
                    source_module=self.name,
                    steps=["Visiter chaque chemin Disallow — ils cachent souvent un indice."],
                ))

    def _find_flags(self, text: str) -> list[str]:
        flags = []
        for match in self.flag_re.finditer(text):
            value = match.group(0).partition("{")[2][:-1]
            if FLAG_VALUE_RE.fullmatch(value):
                flags.append(match.group(0))
        return list(dict.fromkeys(flags))

    def _get(self, scope: Scope, url: str):
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        scope.authorize_url(url)
        opener = make_scoped_opener(scope)
        try:
            with opener.open(req, timeout=10) as resp:
                return resp.status, {k: v for k, v in resp.headers.items()}, resp.read(200000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            body = e.read(200000).decode("utf-8", "replace") if e.fp else ""
            return e.code, ({k: v for k, v in e.headers.items()} if e.headers else {}), body
        except Exception:  # noqa: BLE001
            return None, None, ""
