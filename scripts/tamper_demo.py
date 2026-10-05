"""scripts/tamper_demo.py — show the hash chain catching a single altered entry.

    python -m scripts.tamper_demo [--ledger PATH]   (default: the configured data directory's ledger)

1. verify the chain (valid)
2. change one character of one entry's sealed_sha256 in the file
3. verify again: the chain reports the exact entry and why
4. restore the file byte-for-byte and verify once more
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from core.repository import default_ledger_path, verify_chain

RULE = "-" * 68


def _say(text: str = "") -> None:
    print(text)


def _flip_digest(line: str) -> tuple[str, str, str]:
    """Return (new_line, old_digest, new_digest) with one hex character changed."""
    entry = json.loads(line)
    old = entry["sealed_sha256"]
    new_char = "1" if old[0] != "1" else "2"
    entry["sealed_sha256"] = new_char + old[1:]
    new_line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return new_line, old, entry["sealed_sha256"]


def run(ledger: str) -> int:
    if not os.path.exists(ledger):
        _say(f"No ledger at {ledger}. Analyse an APK first, then run this again.")
        return 1
    with open(ledger, "rb") as fh:
        original = fh.read()
    lines = original.decode("utf-8").splitlines()
    if len(lines) < 3:
        _say(f"The ledger has {len(lines)} entr{'y' if len(lines) == 1 else 'ies'}; "
             "this demo needs at least 3. Analyse a few APKs first.")
        return 1

    target = len(lines) // 2
    _say("MerkleTrust ledger: tamper demo")
    _say(RULE)
    _say(f"Ledger: {ledger}")

    _say()
    _say("[1] Verifying the chain as it is now")
    first = verify_chain(ledger)
    _say(f"    {len(lines)} entries.  Result: {'VALID' if first['valid'] else 'INVALID'}")
    _say("    Every link and every entry hash checks out." if first["valid"] else f"    {first['reason']}")

    try:
        _say()
        _say(f"[2] Changing one character of entry #{target}'s sealed_sha256")
        new_line, old, new = _flip_digest(lines[target])
        lines[target] = new_line
        with open(ledger, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        _say(f"    before: {old}")
        _say(f"    after:  {new}")

        _say()
        _say("[3] Verifying the chain again")
        second = verify_chain(ledger)
        if second["valid"]:
            _say("    Result: VALID  (this should not happen; the demo did not break the chain)")
            return 2
        _say(f"    Result: INVALID, broken at entry #{second['broken_at']}")
        _say(f"    Reason: {second['reason']}")
        intact = second["broken_at"]
        if intact == 1:
            _say("    Entry #0 checks out.")
        elif intact > 1:
            _say(f"    Entries #0 to #{intact - 1} check out.")
        _say(f"    Verification stops at the first break, so entries #{intact + 1} onward were not checked.")
    finally:
        with open(ledger, "wb") as fh:
            fh.write(original)

    _say()
    _say("[4] Restoring the original file and verifying once more")
    with open(ledger, "rb") as fh:
        restored = fh.read() == original
    final = verify_chain(ledger)
    _say(f"    File restored byte-for-byte: {'yes' if restored else 'NO'}")
    _say(f"    Result: {'VALID' if final['valid'] else 'INVALID'}")
    _say(RULE)
    return 0 if (restored and final["valid"]) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Show the ledger detecting a single altered entry.")
    parser.add_argument("--ledger", default=None)
    args = parser.parse_args(argv)
    return run(args.ledger or default_ledger_path())


if __name__ == "__main__":
    sys.exit(main())
