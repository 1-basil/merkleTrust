"""scripts/stress_audit_chain.py — Concurrency stress test of the audit chain.

    python -m scripts.stress_audit_chain [--rounds 8] [--writers 8] [--events 25]

Each round uses a fresh temporary database and key. While CPU-burning processes
keep the machine busy (to widen race windows), several threads append events
concurrently. A round passes only if every event was recorded exactly once,
there is exactly one genesis block, and the chain verifies. Exits non-zero on
any failure. (This is the test that exposed lost events and a duplicate genesis
block before the append path was serialised.)
"""

from __future__ import annotations

import argparse
import multiprocessing
import os
import sys
import tempfile
import threading
from collections import Counter


def _burn(stop) -> None:
    while not stop.is_set():
        sum(i * i for i in range(10_000))


def run_round(writers: int, events: int) -> tuple[bool, str]:
    data = tempfile.mkdtemp(prefix="mt_stress_")
    os.environ.update(MERKLETRUST_DATA_DIR=data, MERKLETRUST_DEV_KEY_DIR=os.path.join(data, "keys"),
                      MERKLETRUST_ENV="test")
    from core import audit
    from core.crypto import get_keyring, reset_key_cache
    from db.database import SessionLocal, configure_database, init_db
    reset_key_cache()
    configure_database("sqlite:///" + os.path.join(data, "stress.db").replace("\\", "/"))
    init_db()

    errors: list[str] = []

    def writer(n: int) -> None:
        for i in range(events):
            try:
                audit.record_event("APK_UPLOADED", f"worker{n}", {"worker": n, "i": i})
            except Exception as exc:
                errors.append(type(exc).__name__)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with SessionLocal() as db:
        blocks = audit.all_blocks(db)
        counts = Counter((b.event_type, b.actor, b.payload_json) for b in blocks)
        duplicates = sum(1 for n in counts.values() if n > 1)
        geneses = sum(1 for b in blocks if b.event_type == "GENESIS")
        valid = audit.verify_chain(blocks, get_keyring())["valid"]
    expected = 1 + writers * events
    ok = len(blocks) == expected and not errors and not duplicates and geneses == 1 and valid
    return ok, (f"blocks={len(blocks)}/{expected} errors={len(errors)} duplicates={duplicates} "
                f"genesis={geneses} chain_valid={valid}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--writers", type=int, default=8)
    parser.add_argument("--events", type=int, default=25)
    args = parser.parse_args(argv)

    stop = multiprocessing.Event()
    burners = [multiprocessing.Process(target=_burn, args=(stop,)) for _ in range(os.cpu_count() or 4)]
    for p in burners:
        p.start()
    failures = 0
    try:
        for r in range(args.rounds):
            ok, detail = run_round(args.writers, args.events)
            failures += not ok
            print(f"round {r}: {'PASS' if ok else 'FAIL'}  {detail}", flush=True)
    finally:
        stop.set()
        for p in burners:
            p.join()
    print(f"\n{args.rounds - failures}/{args.rounds} rounds passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
