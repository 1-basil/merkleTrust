"""scripts/manage_users.py — Create and manage MerkleTrust operator accounts.

    python -m scripts.manage_users create <username> --role admin|analyst
    python -m scripts.manage_users set-password <username>
    python -m scripts.manage_users disable <username>
    python -m scripts.manage_users list

Passwords are prompted for (never passed on the command line, where they would
end up in shell history). For automation, MERKLETRUST_NEW_USER_PASSWORD may be set.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import select

from api.security import create_user, hash_password
from db.database import init_db, session_scope
from db.models import User


def _password() -> str:
    env = os.environ.get("MERKLETRUST_NEW_USER_PASSWORD")
    if env:
        return env
    first = getpass.getpass("Password (min 10 characters): ")
    if first != getpass.getpass("Repeat password: "):
        raise ValueError("passwords do not match")
    return first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage MerkleTrust users")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("create"); p.add_argument("username"); p.add_argument("--role", required=True,
                                                                            choices=["admin", "analyst"])
    p = sub.add_parser("set-password"); p.add_argument("username")
    p = sub.add_parser("disable"); p.add_argument("username")
    sub.add_parser("list")
    args = parser.parse_args(argv)

    init_db()
    try:
        with session_scope() as db:
            if args.cmd == "create":
                user = create_user(db, args.username, _password(), args.role)
                print(f"created {user.role} '{user.username}'")
            elif args.cmd == "list":
                for u in db.scalars(select(User).order_by(User.username)):
                    print(f"{u.username:20} {u.role:8} {'active' if u.active else 'disabled'}")
            else:
                user = db.scalars(select(User).where(User.username == args.username)).first()
                if user is None:
                    raise ValueError(f"no such user {args.username!r}")
                if args.cmd == "disable":
                    user.active = False
                    print(f"disabled '{user.username}'")
                else:
                    user.password_hash = hash_password(_password())
                    print(f"password updated for '{user.username}'")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
