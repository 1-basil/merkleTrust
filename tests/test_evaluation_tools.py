"""Evaluation tooling: dataset integrity and metric computation."""

import json
from pathlib import Path

import pytest

from core.apk_archive import ApkArchive
from scripts.eval_metrics import confusion

pytestmark = pytest.mark.unit
DATASET = Path(__file__).resolve().parent.parent / "evaluation" / "dataset"


def test_confusion_metrics():
    m = confusion([(True, True), (True, False), (False, False), (False, True), (True, True)])
    assert (m["tp"], m["fn"], m["tn"], m["fp"]) == (2, 1, 1, 1)
    assert m["accuracy"] == 0.6 and m["precision"] == 0.6667 and m["recall"] == 0.6667
    assert m["false_positive_rate"] == 0.5 and m["false_negative_rate"] == 0.3333


def test_undefined_ratios_are_not_invented():
    m = confusion([(False, False), (False, False)])
    assert m["precision"] is None and m["recall"] is None and m["f1"] is None
    assert m["accuracy"] == 1.0 and m["false_positive_rate"] == 0.0


def test_dataset_manifest_matches_files():
    manifest = json.loads((DATASET / "manifest.json").read_text(encoding="utf-8"))
    ids = [c["id"] for c in manifest["cases"]]
    assert len(ids) == len(set(ids)) == 32
    for name in manifest["baselines"].values():
        assert (DATASET / name).is_file()
    for case in manifest["cases"]:
        assert (DATASET / case["file"]).is_file(), case["id"]
        assert {"integrity", "risky"} <= set(case["truth"]), case["id"]
        assert case["set"] in ("development", "held_out")
        if case["baseline"]:
            assert case["baseline"] in manifest["baselines"]
            assert {"changed", "unauthorized"} <= set(case["truth"]), case["id"]
    assert sum(c["set"] == "held_out" for c in manifest["cases"]) == 7


def test_dataset_apks_are_well_formed():
    for apk in DATASET.glob("*.apk"):
        if apk.name == "demo_janus_prefix.apk":
            continue                      # deliberately has data before the ZIP
        with ApkArchive(str(apk)) as a:
            assert a.has("AndroidManifest.xml") and a.has("classes.dex"), apk.name
