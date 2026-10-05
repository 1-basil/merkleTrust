"""scripts/coverage_report.py — Line coverage of the test suite, standard library only.

    python -m scripts.coverage_report [pytest args...]

Runs pytest in-process with Python's low-overhead sys.monitoring API (3.12+)
recording which lines of the application packages execute, then prints per-file
and total line coverage. Executable lines are taken from the compiled code
objects (co_lines), the same source of truth coverage.py uses for line coverage.
Used because third-party tools may be unavailable; it measures line (not branch)
coverage.
"""

from __future__ import annotations

import sys
import types
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = ("core", "api", "db")
TOOL_ID = sys.monitoring.COVERAGE_ID


def _tracked(filename: str) -> bool:
    try:
        rel = Path(filename).resolve().relative_to(ROOT)
    except ValueError:
        return False
    return rel.parts[0] in PACKAGES and rel.suffix == ".py"


def _executable_lines(path: Path) -> set[int]:
    code = compile(path.read_text(encoding="utf-8"), str(path), "exec")
    lines: set[int] = set()
    stack = [code]
    while stack:
        co = stack.pop()
        lines.update(line for _, _, line in co.co_lines() if line is not None)
        stack.extend(c for c in co.co_consts if isinstance(c, types.CodeType))
    return lines


def main(argv: list[str]) -> int:
    import pytest

    hits: dict[str, set[int]] = defaultdict(set)

    def on_line(code: types.CodeType, line: int):
        if _tracked(code.co_filename):
            hits[str(Path(code.co_filename).resolve())].add(line)
            return None
        return sys.monitoring.DISABLE

    sys.monitoring.use_tool_id(TOOL_ID, "merkletrust-coverage")
    sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.LINE, on_line)
    sys.monitoring.set_events(TOOL_ID, sys.monitoring.events.LINE)
    try:
        status = pytest.main(["-q", "-p", "no:cacheprovider", *argv])
    finally:
        sys.monitoring.set_events(TOOL_ID, 0)
        sys.monitoring.free_tool_id(TOOL_ID)

    rows, total_exec, total_hit = [], 0, 0
    for pkg in PACKAGES:
        for path in sorted((ROOT / pkg).rglob("*.py")):
            executable = _executable_lines(path)
            executed = hits.get(str(path.resolve()), set()) & executable
            total_exec += len(executable)
            total_hit += len(executed)
            pct = 100.0 * len(executed) / len(executable) if executable else 100.0
            rows.append((str(path.relative_to(ROOT)), len(executable), len(executed), pct))

    print(f"\n{'file':40} {'lines':>6} {'run':>6} {'cover':>7}")
    for name, n, hit, pct in rows:
        print(f"{name:40} {n:6} {hit:6} {pct:6.1f}%")
    print(f"{'TOTAL':40} {total_exec:6} {total_hit:6} {100.0 * total_hit / max(total_exec, 1):6.1f}%")
    return int(status)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
