"""scripts/crosscheck_apksigner.py — Differential check of our signature verifier
against Google's official `apksigner verify` on genuine and tampered APKs.

    python -m scripts.crosscheck_apksigner

Requires the Android SDK (see scripts/apk_builder.py). Exits non-zero on any
disagreement.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from core.apk_archive import ApkArchive, ApkValidationError
from core.apk_signature import locate_signing_block, verify_apk
from scripts.apk_builder import Toolchain
from scripts.apk_mutations import flip_byte, local_header_offset, rewrite_zip

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "apks"
TARGET_SDK = 34  # fixtures target API 34


def ours(path: Path) -> str:
    try:
        with ApkArchive(str(path)) as apk:
            return verify_apk(apk, target_sdk=TARGET_SDK)["status"]
    except ApkValidationError:
        return "rejected"


def official(path: Path, tools: Toolchain) -> str:
    proc = subprocess.run([tools.java, "-jar", str(tools.apksigner_jar), "verify",
                           "--min-sdk-version", "24", str(path)], capture_output=True, text=True)
    return "verified" if proc.returncode == 0 else "rejected"


def build_cases(tmp: Path) -> dict[str, Path]:
    v1v2, v1 = FIXTURES / "signed_v1v2_ec.apk", FIXTURES / "signed_v1only_ec.apk"
    v2 = FIXTURES / "suspicious_v2_ec.apk"
    sf = next(n for n in zipfile.ZipFile(v1).namelist() if n.endswith(".SF"))
    sf_bytes = zipfile.ZipFile(v1).read(sf)
    dex = zipfile.ZipFile(v1v2).read("classes.dex")
    block = locate_signing_block(v2.read_bytes())["block_offset"]
    return {
        "genuine v1+v2 (EC)": v1v2,
        "genuine v2+v3 (RSA)": FIXTURES / "signed_v2v3_rsa.apk",
        "genuine v2 (EC)": v2,
        "v1-only, targetSdk 34": v1,
        "unsigned": FIXTURES / "unsigned.apk",
        "v1: file modified": rewrite_zip(v1, tmp / "a.apk", modify={"assets/config.json": b"x"}),
        "v1: file injected": rewrite_zip(v1, tmp / "b.apk", add={"assets/p.bin": b"x"}),
        "v1: file deleted": rewrite_zip(v1, tmp / "c.apk", remove={"assets/config.json"}),
        "v1: .SF tampered": rewrite_zip(v1, tmp / "d.apk", modify={sf: sf_bytes + b"X: 1\r\n"}),
        "v2 block stripped": rewrite_zip(v1v2, tmp / "e.apk"),
        "v2: header byte flipped": flip_byte(v2, tmp / "f.apk", local_header_offset(v2, "classes.dex") + 10),
        "v2: signed data forged": flip_byte(v2, tmp / "g.apk", block + 56),
        "classes.dex modified": rewrite_zip(v1v2, tmp / "h.apk", modify={"classes.dex": dex + b"\0"}),
    }


def main() -> int:
    tools = Toolchain.discover()
    disagreements = 0
    with tempfile.TemporaryDirectory(prefix="mt_xcheck_") as tmp:
        cases = build_cases(Path(tmp))
        print(f"{'case':28} {'MerkleTrust':12} {'apksigner':10} result")
        for name, path in cases.items():
            mine, theirs = ours(path), official(path, tools)
            agree = (mine == "verified") == (theirs == "verified")
            disagreements += not agree
            print(f"{name:28} {mine:12} {theirs:10} {'agree' if agree else 'DISAGREE'}")
        print(f"\n{len(cases) - disagreements}/{len(cases)} verdicts agree with apksigner")
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
