"""scripts/run_dynamic_evaluation.py — Static-only vs. static + emulator, on the behaviour cases.

    python -m scripts.run_dynamic_evaluation [--observe 20] [--frida <path>]

Needs a running, rooted emulator (scripts/setup_avd.ps1, then
``emulator -avd mt_api30_root``). Each case without a baseline (R* development
and H* held-out samples) goes through the real pipeline with the dynamic engine
enabled; the risk verdict is computed twice from the same engine reports — once
without and once with the dynamic engine's findings — so the only difference is
what was observed at runtime.

Disclosure: the dynamic engine was completed *after* the held-out results of
the static evaluation were known (evaluation/README.md), so on the H* cases this
is not an independent test of the engine; it shows what runtime observation
adds on samples whose behaviour is documented.

Writes evaluation/results/dynamic.{json,md}. Nothing is tuned here.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile

_DATA = tempfile.mkdtemp(prefix="mt_dyn_eval_")
os.environ.update(MERKLETRUST_ENV="test", MERKLETRUST_DATA_DIR=os.path.join(_DATA, "data"),
                  MERKLETRUST_DEV_KEY_DIR=os.path.join(_DATA, "keys"), MERKLETRUST_LOG_LEVEL="WARNING",
                  MERKLETRUST_LOG_JSON="false", MERKLETRUST_DYNAMIC_ENABLED="true")
for _v in ("MERKLETRUST_DATABASE_URL", "MERKLETRUST_SIGNING_KEY_PATH", "MERKLETRUST_TRUSTED_KEYS_DIR"):
    os.environ.pop(_v, None)

import json  # noqa: E402
import platform  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

from scripts.eval_metrics import confusion  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "evaluation" / "dataset"
RESULTS = ROOT / "evaluation" / "results"
RISKY = ("HIGH", "CRITICAL")


def evaluate(observe_s: int, frida: str | None) -> dict:
    from core import orchestrator, scoring
    from core.config import get_settings
    from core.contracts import JobContext

    get_settings.cache_clear()
    os.environ["MERKLETRUST_DYNAMIC_OBSERVE_S"] = str(observe_s)
    if frida:
        os.environ["MERKLETRUST_FRIDA_PATH"] = frida
    manifest = json.loads((DATASET / "manifest.json").read_text(encoding="utf-8"))
    rows, emulator = [], {}
    for case in [c for c in manifest["cases"] if not c["baseline"]]:
        reports = orchestrator.run_job(str(DATASET / case["file"]), root=os.path.join(_DATA, "jobs"))
        dyn = reports.get("dynamic") or {}
        if dyn.get("launched"):
            emulator = dyn["emulator"]
        static_only = {k: v for k, v in reports.items() if k not in ("dynamic", "score", "repository")}
        workspace = tempfile.mkdtemp(dir=_DATA)
        before = scoring.run("eval", JobContext(apk_path="", workspace=workspace, prior=static_only))["risk"]
        after = reports["score"]["risk"]
        runtime = sorted({f["id"] for f in dyn.get("findings", []) if f["id"].startswith("RUNTIME_")})
        rows.append({
            "id": case["id"], "set": case["set"], "description": case["description"],
            "truth_risky": case["truth"]["risky"], "dynamic_status": dyn.get("status"),
            "launched": dyn.get("launched"), "triggers": [t["action"] for t in dyn.get("observation", {}).get("triggers", [])],
            "static": {"level": before["level"], "score": before["score"]},
            "with_dynamic": {"level": after["level"], "score": after["score"]},
            "runtime_findings": runtime,
            "evidence": {f["id"]: f["evidence"] for f in dyn.get("findings", []) if f["id"].startswith("RUNTIME_")},
            "operational": [f"{f['id']}: {f['title']}" for f in dyn.get("findings", [])
                            if f["id"].startswith("DYN_") and f["id"] != "DYN_000"],
            "duration_s": dyn.get("duration_s"),
        })
        print(f"{case['id']}: {before['level']} -> {after['level']}  {', '.join(runtime) or '-'}", flush=True)
    return {"cases": rows, "emulator": emulator}


def summarise(rows: list[dict]) -> dict:
    out = {}
    for name, subset in (("development", [r for r in rows if r["set"] == "development"]),
                         ("held_out", [r for r in rows if r["set"] == "held_out"])):
        out[name] = {
            "static": confusion([(r["truth_risky"], r["static"]["level"] in RISKY) for r in subset]),
            "with_dynamic": confusion([(r["truth_risky"], r["with_dynamic"]["level"] in RISKY) for r in subset]),
        }
    return out


def markdown(raw: dict, summary: dict, env: dict) -> str:
    lines = ["# MerkleTrust — Emulator (dynamic) evaluation", "",
             f"Generated {env['generated']} on {env['platform']} (Python {env['python']}); emulator "
             f"{raw['emulator'].get('serial', '?')}, Android API {raw['emulator'].get('api_level', '?')}, "
             f"rooted: {raw['emulator'].get('rooted', '?')}; observation window {env['observe_s']} s.",
             "Produced by `python -m scripts.run_dynamic_evaluation`. Both columns are computed from the same "
             "engine reports; *with emulator* adds only the dynamic engine's findings.", "",
             "**Disclosure:** the dynamic engine was finished after the held-out results of the static evaluation "
             "were known, so the held-out row is not an independent test of it.", "",
             "## Install warning (risk HIGH/CRITICAL)", "",
             "| Cases | n | Static only: TP / FP / TN / FN | With emulator: TP / FP / TN / FN |", "|---|---|---|---|"]
    for name, label in (("development", "Development R*"), ("held_out", "Held-out H*")):
        s, d = summary[name]["static"], summary[name]["with_dynamic"]
        lines.append(f"| {label} | {s['n']} | {s['tp']} / {s['fp']} / {s['tn']} / {s['fn']} | "
                     f"{d['tp']} / {d['fp']} / {d['tn']} / {d['fn']} |")
    lines += ["", "## Per case", "",
              "| ID | Case | Risky? | Static only | With emulator | Observed at runtime | Notes |", "|---|---|---|---|---|---|---|"]
    for r in raw["cases"]:
        observed = "<br>".join(f"{k}: {v[:90]}" for k, v in r["evidence"].items()) or "nothing suspicious"
        notes = "; ".join(r["operational"]) or (f"triggered: {', '.join(r['triggers'])}" if r["triggers"] else "")
        lines.append(f"| {r['id']} | {r['description']} | {'yes' if r['truth_risky'] else 'no'} | "
                     f"{r['static']['level']} ({r['static']['score']}) | {r['with_dynamic']['level']} "
                     f"({r['with_dynamic']['score']}) | {observed.replace('|', '/')} | {notes.replace('|', '/')} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--observe", type=int, default=20)
    parser.add_argument("--frida", default=None)
    args = parser.parse_args()
    raw = evaluate(args.observe, args.frida)
    if not any(r["launched"] for r in raw["cases"]):
        print("No case was launched in an emulator — is one running? Nothing written.", file=sys.stderr)
        return 1
    summary = summarise(raw["cases"])
    env = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "platform": f"{platform.system()} {platform.release()}", "python": platform.python_version(),
           "observe_s": args.observe}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "dynamic.json").write_text(json.dumps({"environment": env, "summary": summary, **raw}, indent=2),
                                          encoding="utf-8")
    (RESULTS / "dynamic.md").write_text(markdown(raw, summary, env), encoding="utf-8")
    print(f"wrote {RESULTS / 'dynamic.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
