"""scripts/run_benign_risk.py — Risk scores of genuine apps the risk rules were never designed on.

    python -m scripts.run_benign_risk --label before|after [--work DIR]

Measures the false-alarm side of the risk heuristics on eight open-source apps downloaded from
F-Droid (SHA-256 pinned from F-Droid's repository index, 9 October 2026). These apps were chosen
before any rule change and are used only for measurement: the rules are never tuned on them.
Apps are read as bytes only — never installed or run.

Writes evaluation/results/benign_risk_<label>.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

APPS = [
    {"package": "org.fossify.calendar", "version": "1.11.0", "file": "org.fossify.calendar_22.apk",
     "sha256": "4b946bee820b516ef9e4893a7f92ba2aa187201b15915e159c6f04567648f93e"},
    {"package": "org.fossify.messages", "version": "1.9.1", "file": "org.fossify.messages_23.apk",
     "sha256": "95f226c7929adc2699cdb2bc6ead29a704bddb8f55bd92d9b4ecf74bb604f1c6"},
    {"package": "org.fossify.filemanager", "version": "1.6.1", "file": "org.fossify.filemanager_13.apk",
     "sha256": "9e97d2faf55fb2702386c3dc51e38a6b073781016b125701d3ab668419a70008"},
    {"package": "org.schabi.newpipe", "version": "0.29.1", "file": "org.schabi.newpipe_1015_cb84069.apk",
     "sha256": "18447bfb1e06d113edc88df93f471827280de06f6f3d4dc42f56f28b9c1bab79"},
    {"package": "com.github.libretube", "version": "32.1", "file": "com.github.libretube_72.apk",
     "sha256": "792b1e37e7bd6a26d8da1c826a68677465c333633cb2198224cc96c84257d615"},
    {"package": "de.marmaro.krt.ffupdater", "version": "81.0.0", "file": "de.marmaro.krt.ffupdater_179_f4e642b.apk",
     "sha256": "b1a854c248ca3336afd112f8f620c5c8c44c02dd6aac5784199f9931c2377ce6"},
    {"package": "at.bitfire.davdroid", "version": "4.5.20-ose", "file": "at.bitfire.davdroid_405200005.apk",
     "sha256": "df387d8b3ddc3730d88d2bfea939aadb8906cc6cff7de46385a7751d1b536462"},
    {"package": "org.fossify.clock", "version": "1.6.0", "file": "org.fossify.clock_10.apk",
     "sha256": "43cf9f0ec45f1f1ff2df47286622e5b8f3acedaeb07b7f7641b5243dbedca079"},
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--label", required=True)
    parser.add_argument("--work", type=Path, default=ROOT / "data" / "realworld")
    args = parser.parse_args(argv)
    os.environ.setdefault("MERKLETRUST_FUZZY_MAX_DEX_MB", "0")  # risk only; skip the slow fuzzy hash

    from core.findings import normalize
    from core.scoring import score_findings
    from core.static import analyze_apk
    from scripts.run_realworld_evaluation import download

    folder = args.work / "downloads"
    folder.mkdir(parents=True, exist_ok=True)
    rows = []
    for app in APPS:
        path = download(app, folder)
        report = analyze_apk(str(path))
        score = score_findings([normalize(f, "static") for f in report["findings"]])
        rows.append({"package": app["package"], "version": app["version"], "risk": score["level"],
                     "score": score["score"],
                     "contributions": [f"{c['finding_id']}+{c['points']}" for c in score["contributions"]]})
        print(f"{app['package']:28} {score['level']:8} {score['score']:3}  "
              + " ".join(f"{c['finding_id']}+{c['points']}" for c in score["contributions"]))
    flagged = sum(r["risk"] in ("HIGH", "CRITICAL") for r in rows)
    print(f"{flagged}/{len(rows)} genuine apps rated HIGH or CRITICAL")
    out = ROOT / "evaluation" / "results" / f"benign_risk_{args.label}.json"
    out.write_text(json.dumps({"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                               "python": sys.version.split()[0], "label": args.label,
                               "flagged_high_or_critical": flagged, "apps": rows}, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
