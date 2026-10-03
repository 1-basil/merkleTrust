"""Documentation must match the code: routes, cited tests, files, functions, links, counts."""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", ROOT / "evaluation" / "README.md",
        *[p for p in (ROOT / "docs").glob("*.md") if p.name != "AUDIT.md"]]   # AUDIT.md is a historical snapshot


def _text(p):
    return p.read_text(encoding="utf-8")


def _routes():
    from api.routers import audit, auth, baselines, dashboard, scans
    for mod in (auth, scans, baselines, audit, dashboard):
        for r in mod.router.routes:
            for method in r.methods:
                yield method, "/api/v1" + r.path


def test_every_api_route_is_documented():
    arch = _text(ROOT / "docs" / "ARCHITECTURE.md")
    routes = sorted(set(_routes()))
    missing = [f"{m} {p}" for m, p in routes if not re.search(rf"\|\s*{m}\s*\|\s*`{re.escape(p)}`", arch)]
    assert missing == []
    documented = re.findall(r"^\|\s*(GET|POST|PUT|PATCH|DELETE)\s*\|\s*`(/api/v1[^`]*)`", arch, re.M)
    assert sorted(set(documented)) == routes, "documented routes that do not exist"
    assert f"{len(routes)} endpoints" in " ".join(_text(ROOT / "docs" / "REPORT.md").split())


def test_cited_tests_exist():
    defined = set()
    for f in (ROOT / "tests").glob("test_*.py"):
        defined |= set(re.findall(r"^def (test_\w+)", _text(f), re.M))
    files = {f.name for f in (ROOT / "tests").glob("test_*.py")}
    for doc in DOCS:
        for name, star in re.findall(r"(test_[a-z0-9_]+)(\*?)", _text(doc)):
            if name + ".py" in files or name.endswith("_py"):
                continue
            ok = any(d.startswith(name) for d in defined) if star else name in defined
            assert ok, f"{doc.name} cites missing test {name}"


def test_cited_files_and_functions_exist():
    pattern = re.compile(r"`((?:core|api|db|scripts|tests|frontend|migrations)/[\w./-]+?)(?:::(\w+))?`")
    for doc in DOCS:
        for path, func in pattern.findall(_text(doc)):
            target = ROOT / path
            assert target.exists(), f"{doc.name} cites missing file {path}"
            if func:
                assert re.search(rf"^\s*(def|class) {func}\b", _text(target), re.M), \
                    f"{doc.name} cites missing {path}::{func}"


def test_relative_links_resolve():
    for doc in DOCS + list((ROOT / "docs" / "team").glob("*.md")):
        for link in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", _text(doc)):
            if link.startswith(("http://", "https://", "mailto:")):
                continue
            assert (doc.parent / link).resolve().exists(), f"{doc.name}: broken link {link}"


def test_stated_counts_match_code():
    from core.audit import EVENTS
    from core.findings import CATALOG
    def flat(p):
        return " ".join(_text(p).split())          # ignore line wrapping
    arch, report = flat(ROOT / "docs" / "ARCHITECTURE.md"), flat(ROOT / "docs" / "REPORT.md")
    assert f"{len(CATALOG)} entries" in arch
    assert f"catalogue of {len(CATALOG)} finding types" in report
    for event in EVENTS:
        assert event in arch or event.split("_")[0] in arch, event
