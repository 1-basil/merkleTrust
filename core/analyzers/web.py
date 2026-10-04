"""core/analyzers/web.py — HTML page and JavaScript analysis (stdlib html.parser).

  WEB_MISSING_SRI              external <script src> / <link rel=stylesheet|preload|modulepreload>
                               without a valid Subresource Integrity hash
  WEB_DANGEROUS_INLINE_SCRIPT  eval(), new Function(), document.write(), string timers,
                               insertAdjacentHTML and non-literal innerHTML/outerHTML
                               assignments — in inline scripts, event-handler attributes,
                               javascript: URLs, or a standalone .js file
  WEB_INSECURE_FORM_ACTION     forms posting over cleartext HTTP, to a javascript:/data: URL,
                               or to another domain (the page's own domain comes from
                               <base>, rel=canonical or og:url; when it is unknown, only
                               password forms posting to an absolute URL are flagged)
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from core.analyzers._common import MAX_EVIDENCE_ITEMS, build_report
from core.contracts import JobContext
from core.findings import finding

DANGEROUS_JS = [
    ("eval()", re.compile(r"\beval\s*\(")),
    ("new Function()", re.compile(r"\bnew\s+Function\s*\(")),
    ("document.write()", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(")),
    ("string passed to setTimeout/setInterval", re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]")),
    ("insertAdjacentHTML()", re.compile(r"\.\s*insertAdjacentHTML\s*\(")),
    # Assigning a plain string literal ("", '<b>x</b>') is safe; anything built at runtime is not.
    ("innerHTML/outerHTML assignment",
     re.compile(r"\.\s*(?:inner|outer)HTML\s*\+?=(?!=)(?!\s*(['\"])[^'\"\\+]*\1\s*(?:;|$|\}))", re.M)),
]
_SRI = re.compile(r"^\s*(sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}(\s+(sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2})*\s*$")
_JS_TYPES = {"", "text/javascript", "application/javascript", "module", "text/ecmascript",
             "application/ecmascript", "text/jscript"}
_SRI_LINK_RELS = {"stylesheet", "preload", "modulepreload"}


def scan_js(code: str, where: str, line_offset: int = 1) -> list[str]:
    hits = []
    for label, pattern in DANGEROUS_JS:
        for m in pattern.finditer(code):
            line = line_offset + code.count("\n", 0, m.start())
            snippet = code[max(0, m.start() - 20):m.end() + 30].strip().replace("\n", " ")
            hits.append(f"{label} in {where} at line {line}: {snippet[:90]}")
    return hits


def _is_external(url: str) -> bool:
    return url.strip().lower().startswith(("http://", "https://", "//"))


def _host(url: str) -> str | None:
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return None
    return host.lower().removeprefix("www.") if host else None


class _PageAudit(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.missing_sri: list[str] = []
        self.dangerous: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.origin_hints: list[str] = []
        self.external: list[str] = []
        self._script: dict[str, Any] | None = None
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        line = self.getpos()[0]
        for name, value in a.items():
            if name.startswith("on") and value:
                self.dangerous += scan_js(value, f"<{tag} {name}> handler", line)
            elif name in ("href", "src", "action") and value.strip().lower().startswith("javascript:"):
                self.dangerous += scan_js(value, f"<{tag} {name}> javascript: URL", line)

        if tag == "base" and a.get("href"):
            self.origin_hints.append(a["href"])
        elif tag == "link" and "canonical" in a.get("rel", "").lower().split() and a.get("href"):
            self.origin_hints.append(a["href"])
        elif tag == "meta" and a.get("property", "").lower() == "og:url" and a.get("content"):
            self.origin_hints.append(a["content"])

        if tag == "script":
            src = a.get("src", "")
            if src and _is_external(src):
                self.external.append(src)
                if not _SRI.match(a.get("integrity", "")):
                    self.missing_sri.append(f"<script src=\"{src[:120]}\"> at line {line}")
            is_js = a.get("type", "").strip().lower() in _JS_TYPES
            self._script = {"line": line, "parts": []} if not src and is_js else None
        elif tag == "link":
            rels = set(a.get("rel", "").lower().split())
            href = a.get("href", "")
            if rels & _SRI_LINK_RELS and href and _is_external(href):
                self.external.append(href)
                if not _SRI.match(a.get("integrity", "")):
                    self.missing_sri.append(f"<link rel=\"{a['rel']}\" href=\"{href[:120]}\"> at line {line}")
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(),
                          "line": line, "password": False}
            self.forms.append(self._form)
        elif tag == "input" and a.get("type", "").lower() == "password" and self._form is not None:
            self._form["password"] = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag == "script":
            self._script = None

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script["parts"].append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._script is not None:
            self.dangerous += scan_js("".join(self._script["parts"]), "inline <script>", self._script["line"])
            self._script = None
        elif tag == "form":
            self._form = None


def _form_problems(forms: list[dict[str, Any]], page_host: str | None) -> tuple[list[str], str]:
    """Evidence lines and the worst severity among the form issues."""
    problems, severity = [], "medium"
    for f in forms:
        action, where = f["action"].strip(), f"<form> at line {f['line']}"
        low = action.lower()
        target = _host(action) if _is_external(action) else None
        if low.startswith("http://"):
            problems.append(f"{where} submits over cleartext HTTP to {action[:120]}")
            severity = "high"
        elif low.startswith(("javascript:", "data:")):
            problems.append(f"{where} submits to a {low.split(':', 1)[0]}: URL")
        elif target and page_host and target != page_host and not target.endswith("." + page_host):
            problems.append(f"{where} submits to {target}, not the page's own domain {page_host}"
                            + (" (password field)" if f["password"] else ""))
            if f["password"]:
                severity = "high"
        elif target and not page_host and f["password"]:
            problems.append(f"{where} posts a password to the absolute address {target}; "
                            "the page does not declare its own domain")
            severity = "high"
    return problems, severity


def analyze_html(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    audit = _PageAudit()
    audit.feed(text)
    audit.close()
    page_host = next((h for h in map(_host, audit.origin_hints) if h), None)
    findings = []
    if audit.missing_sri:
        findings.append(finding("WEB_MISSING_SRI", f"{len(audit.missing_sri)} external resource(s) without "
                                f"integrity: " + "; ".join(audit.missing_sri[:MAX_EVIDENCE_ITEMS])))
    if audit.dangerous:
        findings.append(finding("WEB_DANGEROUS_INLINE_SCRIPT",
                                "; ".join(audit.dangerous[:MAX_EVIDENCE_ITEMS])))
    problems, severity = _form_problems(audit.forms, page_host)
    if problems:
        points = 15 if severity == "high" else 8
        findings.append(finding("WEB_INSECURE_FORM_ACTION", "; ".join(problems[:MAX_EVIDENCE_ITEMS]),
                                severity=severity, points=points))
    return findings, {"format": "html", "page_host": page_host, "external_resources": audit.external[:100],
                      "resources_missing_sri": len(audit.missing_sri), "forms": len(audit.forms),
                      "dangerous_constructs": len(audit.dangerous)}


def analyze_js(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    hits = scan_js(text, "script")
    findings = [finding("WEB_DANGEROUS_INLINE_SCRIPT", "; ".join(hits[:MAX_EVIDENCE_ITEMS]))] if hits else []
    return findings, {"format": "javascript", "dangerous_constructs": len(hits)}


def analyze(data: bytes, mime_type: str = "text/html") -> tuple[list[dict[str, Any]], dict[str, Any]]:
    text = data.decode("utf-8", errors="replace").lstrip("\ufeff")
    return analyze_js(text) if mime_type == "application/javascript" else analyze_html(text)


def run(job_id: str, ctx: JobContext) -> dict:
    with open(ctx.target_path, "rb") as fh:
        data = fh.read()
    findings, details = analyze(data, ctx.mime_type)
    return build_report(ctx, job_id, "web", findings, details)
