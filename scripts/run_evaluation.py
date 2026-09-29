"""scripts/run_evaluation.py — Week 4 Multi-APK Benchmark and Evaluation Runner.

Executes the complete MerkleTrust pipeline on:
  1. apks/clean_baseline.apk       — Baseline build registration
  2. apks/tampered_repackaged.apk   — Repackaged build (Merkle diff, file localization, cert break)
  3. apks/malicious_sample.apk      — Suspicious build (dangerous APIs, DCL, network IOCs)

Generates comparison metrics and prints a structured evaluation summary.
"""

import os
import sys
import json
import tempfile

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import run_job
from scripts.create_test_apks import (
    create_clean_baseline,
    create_tampered_repackaged,
    create_malicious_sample,
)


def run_evaluation():
    print("=" * 75)
    print("      MERKLETRUST -- MULTI-APK DIFFERENTIAL EVALUATION RUNNER")
    print("=" * 75 + "\n")

    clean_apk = create_clean_baseline()
    tampered_apk = create_tampered_repackaged()
    malicious_apk = create_malicious_sample()

    eval_root = os.path.join(os.getcwd(), "jobs")
    os.makedirs(eval_root, exist_ok=True)

    results = []

    # 1. Clean Baseline
    print("\n[+] 1. Running Clean Baseline APK...")
    rep_clean = run_job(clean_apk, root=eval_root)
    results.append({
        "sample": "clean_baseline.apk",
        "sha256": rep_clean["integrity"]["sha256"][:16] + "...",
        "role": rep_clean["tamper"].get("role"),
        "changed_chunks": len(rep_clean["tamper"].get("changed_chunks", [])),
        "changed_files": len(rep_clean["tamper"].get("changed_files", [])),
        "cert_changed": rep_clean["tamper"].get("certificate_changed"),
        "score": rep_clean["score"].get("score"),
        "verdict": rep_clean["score"].get("verdict"),
        "merkle_root": rep_clean["integrity"].get("merkle_root")[:16] + "...",
        "block_height": rep_clean["repository"].get("sim_block", {}).get("height", 0),
    })

    # 2. Tampered APK
    print("\n[+] 2. Running Tampered / Repackaged APK...")
    rep_tamper = run_job(tampered_apk, root=eval_root)
    results.append({
        "sample": "tampered_repackaged.apk",
        "sha256": rep_tamper["integrity"]["sha256"][:16] + "...",
        "role": rep_tamper["tamper"].get("role"),
        "changed_chunks": len(rep_tamper["tamper"].get("changed_chunks", [])),
        "changed_files": len(rep_tamper["tamper"].get("changed_files", [])),
        "cert_changed": rep_tamper["tamper"].get("certificate_changed"),
        "score": rep_tamper["score"].get("score"),
        "verdict": rep_tamper["score"].get("verdict"),
        "merkle_root": rep_tamper["integrity"].get("merkle_root")[:16] + "...",
        "block_height": rep_tamper["repository"].get("sim_block", {}).get("height", 0),
    })

    # 3. Malicious APK
    print("\n[+] 3. Running Malicious Sample APK...")
    rep_mal = run_job(malicious_apk, root=eval_root)
    results.append({
        "sample": "malicious_sample.apk",
        "sha256": rep_mal["integrity"]["sha256"][:16] + "...",
        "role": rep_mal["tamper"].get("role"),
        "changed_chunks": len(rep_mal["tamper"].get("changed_chunks", [])),
        "changed_files": len(rep_mal["tamper"].get("changed_files", [])),
        "cert_changed": rep_mal["tamper"].get("certificate_changed"),
        "score": rep_mal["score"].get("score"),
        "verdict": rep_mal["score"].get("verdict"),
        "merkle_root": rep_mal["integrity"].get("merkle_root")[:16] + "...",
        "block_height": rep_mal["repository"].get("sim_block", {}).get("height", 0),
    })

    # Print Comparison Table
    print("\n" + "=" * 90)
    print(f"{'Sample Name':<25} {'Role':<12} {'Root':<18} {'Diff Chunks':<12} {'Score':<8} {'Verdict':<12}")
    print("-" * 90)
    for r in results:
        print(f"{r['sample']:<25} {r['role']:<12} {r['merkle_root']:<18} {r['changed_chunks']:<12} {r['score']:<8} {r['verdict']:<12}")
    print("=" * 90)

    # Save summary
    out_path = os.path.join("data", "evaluation_summary.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nEvaluation summary saved to: {out_path}\n")


if __name__ == "__main__":
    run_evaluation()
