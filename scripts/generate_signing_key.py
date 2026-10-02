"""scripts/generate_signing_key.py — Create an ECDSA P-256 signing key for MerkleTrust.

    python -m scripts.generate_signing_key --out ~/.merkletrust/keys/prod.pem [--encrypt]

The private key is written with owner-only permissions and must live OUTSIDE the
repository (the script refuses paths inside it). With --encrypt, the password is
read from the MERKLETRUST_SIGNING_KEY_PASSWORD environment variable or prompted for.
The script prints the key ID, the public key, and the environment variables to set.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from core.crypto import key_id_for, public_key_pem, write_private_key

REPO_ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, type=Path, help="where to write the private key (PEM)")
    parser.add_argument("--encrypt", action="store_true", help="encrypt the PEM with a password")
    args = parser.parse_args(argv)

    out = args.out.expanduser().resolve()
    if out == REPO_ROOT or REPO_ROOT in out.parents:
        print(f"refusing to write a private key inside the repository ({REPO_ROOT})", file=sys.stderr)
        return 2
    if out.exists():
        print(f"{out} already exists; refusing to overwrite", file=sys.stderr)
        return 2

    password = None
    if args.encrypt:
        password = os.environ.get("MERKLETRUST_SIGNING_KEY_PASSWORD") or getpass.getpass("Key password: ")
        if len(password) < 12:
            print("password must be at least 12 characters", file=sys.stderr)
            return 2

    key = ec.generate_private_key(ec.SECP256R1())
    write_private_key(key, out, password)
    pub_path = out.with_suffix(".pub.pem")
    pub_path.write_text(public_key_pem(key.public_key()), encoding="ascii")

    print(f"key id:       {key_id_for(key.public_key())}")
    print(f"private key:  {out}")
    print(f"public key:   {pub_path}")
    print("\nSet:")
    print(f"  MERKLETRUST_SIGNING_KEY_PATH={out}")
    if password:
        print("  MERKLETRUST_SIGNING_KEY_PASSWORD=<the password you chose>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
