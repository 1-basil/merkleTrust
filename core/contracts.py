"""
core/contracts.py  —  the only file all four of us must agree on.

Every engine is a function with this exact signature:

    def run(job_id: str, ctx: JobContext) -> dict

Nothing else. No Flask, no FastAPI, no argparse inside your engine.
Basil's orchestrator builds the JobContext and calls you.

Owner of this file: Basil. Changes only by PR + message in the group.
"""

from dataclasses import dataclass, field
from typing import Any
import json
import os


# ---------------------------------------------------------------- input ----

@dataclass
class JobContext:
    """This is the ONLY input your engine receives (besides job_id)."""

    apk_path: str | None = None
    # Absolute path to the APK on disk, already validated and quarantined.
    # Example: "/srv/merkletrust/quarantine/a3f9...c1.apk"
    # It is read-only. Never move, rename or delete it.

    workspace: str | None = None
    # Absolute path to THIS job's folder. Already created by the orchestrator.
    # Example: "/srv/merkletrust/jobs/8d2c1e40-.../"
    # Write your JSON and all your scratch files inside here, nowhere else.

    prior: dict[str, dict] = field(default_factory=dict)
    # Reports from engines that already finished, keyed by engine name:
    #   "integrity" | "static" | "tamper" | "dynamic" | "score"
    # These are plain dicts loaded from the JSON files. Read-only.
    # A key is present only if that engine ran before you. See the table below.

    db: Any = None
    # SQLAlchemy Session. Use it ONLY for your own tables.
    # If you don't need the DB in v1, ignore it and just return the dict.

    config: dict = field(default_factory=dict)
    # Tool paths and tunables from config.yaml, e.g.
    #   {"apktool": "/opt/apktool.jar", "jadx": "/opt/jadx/bin/jadx",
    #    "chunk_size": 65536, "emulator_avd": "mt_api30_root",
    #    "dynamic_timeout_s": 90}
    # Never hardcode a tool path. Read it from here.

    target_path: str | None = None
    # Content-neutral name for apk_path: the analysed file, whatever its type.
    # Pass either one; the other is filled in so APK engines keep working.

    mime_type: str = "application/octet-stream"
    file_category: str = "apk"
    # Set by the orchestrator from core.detector (magic bytes, not the extension):
    #   "apk" | "image" | "video" | "audio" | "web" | "doc"
    # The default keeps every existing caller on the APK pipeline.

    def __post_init__(self) -> None:
        if self.workspace is None:
            raise TypeError("JobContext requires a workspace")
        if self.target_path is None:
            self.target_path = self.apk_path
        elif self.apk_path is None:
            self.apk_path = self.target_path

    def out(self, name: str) -> str:
        """Path for your output file: ctx.out('static.json')"""
        return os.path.join(self.workspace, name)

    def subdir(self, name: str) -> str:
        """Create and return your scratch folder: ctx.subdir('static')"""
        p = os.path.join(self.workspace, name)
        os.makedirs(p, exist_ok=True)
        return p


class EngineError(Exception):
    """Raise this for an unrecoverable failure. Orchestrator marks the
    engine 'failed' and continues with the rest of the pipeline."""


# --------------------------------------------------------------- output ----
#
# Your run() must do TWO things:
#   1. write the dict to ctx.out("<yourname>.json")
#   2. return the same dict
#
# Use this helper so the file format is identical for everyone:

def emit(ctx: JobContext, name: str, payload: dict) -> dict:
    with open(ctx.out(name), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return payload


# Every report, whatever the engine, must contain these four keys:
#
#   "job_id":  str            the job_id you were passed
#   "engine":  str            "integrity" | "static" | "tamper" | "dynamic" | ...
#   "status":  str            "ok" | "partial"     (never "failed" — raise instead)
#   "findings": list[dict]    [{"id": "...", "severity": "...",
#                               "title": "...", "evidence": "..."}]
#                             severity is one of: info|low|medium|high|critical
#
# "findings" is how your work reaches the trust score. Basil's rule engine
# reads ONLY this list plus a few named fields. If you find something bad and
# don't put it in findings, it does not affect the score.
#
# Everything else in your dict is engine-specific — see docs/ARCHITECTURE.md §2.


# ------------------------------------------------------- who reads what ----
#
#  engine      job_id  apk_path  workspace  ctx.prior contains
#  ---------   ------  --------  ---------  -----------------------------------
#  integrity     yes     yes        yes     {}                        (runs first)
#  static        yes     yes        yes     {}                        (runs first)
#  tamper        yes     no         yes     integrity, static
#  dynamic       yes     yes        yes     integrity, static, tamper
#  score         yes     no         yes     integrity, static, tamper, dynamic
#  repository    yes     no         yes     all of the above + score
#
#  If a key you expect is missing from ctx.prior, that engine failed.
#  Degrade gracefully: return status "partial" with a finding, do not crash.


# ----------------------------------------------------------- the stubs ----
#
# Copy your own function into your own file. Delete the others.

def run_integrity(job_id: str, ctx: JobContext) -> dict:
    """AJAY — core/integrity.py

    IN : ctx.apk_path, ctx.config["chunk_size"]
    OUT: integrity.json

    {"job_id", "engine": "integrity", "status", "findings": [],
     "sha256": str, "file_size": int, "file_count": int,
     "files": [{"path", "sha256", "size", "category"}],   <- authoritative
     "merkle_root": str,                                  <- root over files[]
     "chunk_size": int, "chunk_count": int,
     "chunks": [{"index", "offset", "length", "hash"}],   <- forensics only
     "chunk_merkle_root": str, "tree_depth": int,
     "file_map": [{"path", "offset", "length", "sha256"}]}
    """
    raise NotImplementedError


def run_static(job_id: str, ctx: JobContext) -> dict:
    """ASHWINI — core/static/__init__.py

    IN : ctx.apk_path, ctx.config["apktool"], ctx.config["jadx"]
    OUT: static.json

    Keys beyond the common four:
      manifest_format, package_name, version_name, version_code, min_sdk, target_sdk,
      permissions[], declared_permissions[], application{}, components{},
      component_details[], certificate{}, signature{status, schemes_present, schemes,
      certificate_verified, errors}, native_libs[], dex{files, class_count,
      sensitive_classes}, iocs{urls, ips, domains, emails}, dangerous_apis[],
      artifacts{}   <- only when the optional decompilers ran

    Decompile into ctx.subdir("static"). Do not write outside it.
    """
    raise NotImplementedError


def run_tamper(job_id: str, ctx: JobContext) -> dict:
    """ASHWINI — core/tamper.py

    IN : ctx.prior["integrity"]  -> files[] (per-file SHA-256), merkle_root, chunks[]
         ctx.prior["static"]     -> package_name, certificate, signature, permissions,
                                    component_details
         ctx.db                  -> trusted_baselines table (core.baselines)
    OUT: tamper.json

    Logic:
      look up the package's active APPROVED baseline (never auto-created;
      baselines are enrolled and approved by an administrator)
      if none   -> integrity.status "NO_BASELINE"
      re-verify the baseline row (signature, Merkle root, profile hash);
      if invalid -> integrity.status "BASELINE_INVALID"
      else      -> per-file diff, certificate/version/profile diff, Merkle proofs;
                   integrity.status CLEAN | MODIFIED | CERTIFICATE_CHANGED

    Key output for Bhavish:
      "suspicious_targets": [{"type": "class"|"service"|"url",
                              "value": str, "reason": str}]
      Empty list is valid. Bhavish must handle empty.
    """
    raise NotImplementedError


def run_dynamic(job_id: str, ctx: JobContext) -> dict:
    """BHAVISH — core/dynamic/__init__.py

    IN : ctx.apk_path
         ctx.prior["static"]["package_name"]    -> what to launch
         ctx.prior["static"]["components"]      -> activities to poke
         ctx.prior["tamper"]["suspicious_targets"] -> what to hook with Frida
         ctx.config["emulator_avd"], ctx.config["dynamic_timeout_s"]
    OUT: dynamic.json

    {"job_id", "engine": "dynamic", "status", "findings": [],
     "emulator": {"avd", "api_level", "rooted"},
     "installed": bool, "launched": bool, "duration_s": int,
     "network": [{"ts","proto","dst_ip","dst_port","host","sni","bytes"}],
     "dns": [], "file_ops": [], "process_events": [],
     "hooks": [{"ts","target","api","args_sample"}],
     "runtime_permissions": [],
     "artifacts": {"pcap": "dynamic/capture.pcap",
                   "logcat": "dynamic/logcat.txt"}}

    Timebox yourself with dynamic_timeout_s. If the emulator never boots,
    return status "partial" with a finding — do not hang the pipeline.
    """
    raise NotImplementedError


def run_score(job_id: str, ctx: JobContext) -> dict:
    """BASIL — core/scoring.py

    IN : every findings[] in ctx.prior (normalised through core/findings.py),
         tamper.integrity
    OUT: score.json

    {"job_id", "engine": "score", "status", "findings": [],
     "analysis_complete": bool, "missing_engines": [],
     "integrity": {"status", "reasons"},
     "risk": {"score": int 0-100 | None, "level": LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN,
              "contributions": [...], "suppressed_duplicates": [...]},
     "verdict": {"code", "headline", "summary"},
     "all_findings": [...], "notes": [...], "inputs": {...}}
    """
    raise NotImplementedError


def run_repository(job_id: str, ctx: JobContext) -> dict:
    """AJAY — core/repository.py

    IN : the merged report (all of ctx.prior)
    OUT: repo_entry.json

    Steps: report_sha256 = SHA-256(canonical JSON of the engine reports)
           -> append an ANALYSIS_COMPLETED block to the audit chain (core.audit,
              "Cryptographically Linked Blockchain Simulation"): the block hash
              covers the previous block's hash and the payload hash, and the
              block header is ECDSA-signed
           -> if integrity failed, also append an INTEGRITY_ALERT block

    {"job_id", "engine": "repository", "status", "findings": [],
     "report_sha256", "block_index", "block_hash", "previous_hash",
     "payload_hash", "key_id", "signature", "timestamp", "alert_block_index"}
    """
    raise NotImplementedError


# ------------------------------------------------- run yours standalone ----
#
# Nobody should need the orchestrator to test their own engine:
#
#   if __name__ == "__main__":
#       import sys, tempfile, json
#       ctx = JobContext(apk_path=sys.argv[1],
#                        workspace=tempfile.mkdtemp(),
#                        prior=json.load(open(sys.argv[2])) if len(sys.argv) > 2 else {},
#                        config={"chunk_size": 65536})
#       print(json.dumps(run("local-test", ctx), indent=2))
#
# For tamper and dynamic, pass a merged.json "reports" object from a previous
# job (data/jobs/<id>/merged.json) as argv[2].
