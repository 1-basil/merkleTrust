"""api/security.py — Password hashing and login sessions.

Passwords: scrypt (memory-hard KDF from the Python standard library) with a
random 16-byte salt per user; verification uses a constant-time comparison.

Sessions: the client receives a random 256-bit bearer token. The database
stores only SHA-256(token), so a leaked database does not leak usable tokens.
Sessions expire and can be revoked (logout). Tokens travel in the
Authorization header, not in cookies, so cross-site requests cannot carry them
(no CSRF exposure).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import AuthSession, User

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
MIN_PASSWORD_LENGTH = 10
# Pre-computed hash used to keep login timing similar for unknown usernames.
_DUMMY_HASH = None


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p),
                                dklen=len(digest_hex) // 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _naive_utc(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def authenticate(db: Session, username: str, password: str) -> User | None:
    global _DUMMY_HASH
    user = db.scalars(select(User).where(User.username == username)).first()
    if user is None or not user.active:
        if _DUMMY_HASH is None:
            _DUMMY_HASH = hash_password("timing-equaliser-not-a-real-password")
        verify_password(password, _DUMMY_HASH)
        return None
    return user if verify_password(password, user.password_hash) else None


def create_session(db: Session, user: User, ttl_minutes: int) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    db.add(AuthSession(token_hash=_token_hash(token), user_id=user.id, expires_at=_naive_utc(expires)))
    db.flush()
    return token, expires


def resolve_session(db: Session, token: str) -> AuthSession | None:
    if not token or len(token) > 256:
        return None
    s = db.scalars(select(AuthSession).where(AuthSession.token_hash == _token_hash(token))).first()
    if s is None or s.revoked_at is not None or not s.user.active:
        return None
    if _naive_utc(s.expires_at) <= _naive_utc(datetime.now(timezone.utc)):
        return None
    return s


def revoke_session(db: Session, session: AuthSession) -> None:
    session.revoked_at = _naive_utc(datetime.now(timezone.utc))
    db.flush()


def create_user(db: Session, username: str, password: str, role: str) -> User:
    if role not in ("admin", "analyst"):
        raise ValueError("role must be 'admin' or 'analyst'")
    if not username or len(username) > 64 or not username.replace("_", "").replace("-", "").replace(".", "").isalnum():
        raise ValueError("username must be 1-64 characters: letters, digits, '.', '-', '_'")
    if db.scalars(select(User).where(User.username == username)).first():
        raise ValueError(f"user {username!r} already exists")
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()
    return user
