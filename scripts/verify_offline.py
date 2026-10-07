"""scripts/verify_offline.py — Standalone Zero-Trust Offline Verifier CLI.

Enables auditors and automated CI systems to verify MerkleTrust audit bundles,
RFC 6962 Merkle tree proofs, report sealing, and ECDSA P-256 signatures completely offline.

Usage:
    python -m scripts.verify_offline --bundle <bundle.json> [--file <target.apk>] [--pubkey <key.pem>]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.offline_verifier import verify_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="MerkleTrust Standalone Zero-Trust Offline Verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--bundle", "-b", required=True, type=Path,
                        help="Path to the exported MerkleTrust verification bundle JSON")
    parser.add_argument("--file", "-f", type=Path, default=None,
                        help="Optional path to the physical APK/artifact to verify against the manifest")
    parser.add_argument("--pubkey", "-k", type=Path, default=None,
                        help="Optional trusted public key PEM file (overrides key inside the bundle)")
    parser.add_argument("--json", action="store_true",
                        help="Output results in JSON format")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Only return exit code (0 = valid, 1 = invalid)")

    args = parser.parse_args(argv)

    if not args.bundle.is_file():
        if not args.quiet:
            sys.stderr.write(f"Error: Bundle file not found: {args.bundle}\n")
        return 2

    try:
        with open(args.bundle, encoding="utf-8") as fh:
            bundle_data = json.load(fh)
    except Exception as exc:
        if not args.quiet:
            sys.stderr.write(f"Error reading bundle JSON: {exc}\n")
        return 2

    pubkey_pem = args.pubkey.read_text(encoding="utf-8") if args.pubkey and args.pubkey.is_file() else None

    result = verify_bundle(bundle_data, target_file_path=args.file, trusted_pubkey_pem=pubkey_pem)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.valid else 1

    if not args.quiet:
        print("\n" + "=" * 65)
        print("  MERKLETRUST ZERO-TRUST OFFLINE VERIFICATION")
        print("=" * 65)
        print(f"  Scan ID   : {bundle_data.get('scan_id', 'Unknown')}")
        print(f"  Artifact  : {bundle_data.get('filename', 'Unknown')}")
        print(f"  SHA-256   : {bundle_data.get('sha256', 'Unknown')}")
        print(f"  Key ID    : {bundle_data.get('key_id', 'Unknown')}")
        print("-" * 65)
        print("  VERIFICATION STEPS:")
        for step in result.steps:
            icon = "[PASS]" if step.passed else "[FAIL]"
            color_prefix = "\033[92m" if step.passed else "\033[91m"
            reset = "\033[0m"
            print(f"  {icon} {step.name:<28} : {step.details}")
        print("-" * 65)
        if result.valid:
            print("  STATUS: [VERIFIED] All cryptographic proofs confirmed offline.")
        else:
            print(f"  STATUS: [TAMPERED] Verification failed with {len(result.errors)} error(s):")
            for err in result.errors:
                print(f"    - {err}")
        print("=" * 65 + "\n")

    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())
