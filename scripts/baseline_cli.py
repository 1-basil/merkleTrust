"""scripts/baseline_cli.py — Administrator tool for trusted baselines.

    python -m scripts.baseline_cli enroll  <apk> --by <admin>
    python -m scripts.baseline_cli approve <id>  --by <admin> [--note TEXT]
    python -m scripts.baseline_cli reject  <id>  --by <admin> --reason TEXT
    python -m scripts.baseline_cli revoke  <id>  --by <admin> --reason TEXT
    python -m scripts.baseline_cli list    [--package NAME]
    python -m scripts.baseline_cli verify  <id>

Uses the configured database and signing key (see core/config.py).
"""

from __future__ import annotations

import argparse
import json
import sys

from core.baselines import BaselineError, BaselineNotFound, BaselineService, to_dict
from db.database import init_db, session_scope


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage MerkleTrust trusted baselines")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("enroll"); p.add_argument("apk"); p.add_argument("--by", required=True)
    p = sub.add_parser("approve"); p.add_argument("id", type=int); p.add_argument("--by", required=True)
    p.add_argument("--note")
    for name in ("reject", "revoke"):
        p = sub.add_parser(name); p.add_argument("id", type=int); p.add_argument("--by", required=True)
        p.add_argument("--reason", required=True)
    p = sub.add_parser("list"); p.add_argument("--package")
    p = sub.add_parser("verify"); p.add_argument("id", type=int)
    args = parser.parse_args(argv)

    init_db()
    try:
        with session_scope() as db:
            svc = BaselineService(db)
            if args.cmd == "enroll":
                b, review = svc.enroll(args.apk, args.by)
                out = {"baseline": to_dict(b), "review_against_active": review and {
                    "status": review["status"], "reasons": review["reasons"], "counts": review["counts"]}}
            elif args.cmd == "approve":
                out = to_dict(svc.approve(args.id, args.by, args.note))
            elif args.cmd == "reject":
                out = to_dict(svc.reject(args.id, args.by, args.reason))
            elif args.cmd == "revoke":
                out = to_dict(svc.revoke(args.id, args.by, args.reason))
            elif args.cmd == "list":
                out = [{k: v for k, v in to_dict(b).items() if k in
                        ("id", "package_name", "baseline_version", "status", "app_version_name",
                         "certificate_sha256", "file_count", "approved_by")} for b in svc.list(args.package)]
            else:
                out = svc.verify(args.id)
    except (BaselineError, BaselineNotFound) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
