"""api/deps.py — Request dependencies: database session, authentication, roles, rate limits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from api.errors import ApiError
from api.ratelimit import limiter
from api.security import resolve_session
from core.config import Settings, get_settings
from db.database import SessionLocal, get_engine
from db.models import AuthSession


def get_db() -> Iterator[Session]:
    get_engine()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def settings_dep(request: Request) -> Settings:
    """The settings of the running app (so create_app(settings=...) overrides apply everywhere)."""
    return getattr(request.app.state, "settings", None) or get_settings()


@dataclass(frozen=True)
class CurrentUser:
    id: int
    username: str
    role: str
    session: AuthSession

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def current_user(request: Request, db: Session = Depends(get_db)) -> CurrentUser:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ApiError(401, "Sign in required.", headers={"WWW-Authenticate": "Bearer"})
    session = resolve_session(db, token.strip())
    if session is None:
        raise ApiError(401, "Your session is invalid or has expired. Please sign in again.",
                       headers={"WWW-Authenticate": "Bearer"})
    user = session.user
    request.state.username = user.username
    return CurrentUser(user.id, user.username, user.role, session)


def require_admin(user: CurrentUser = Depends(current_user)) -> CurrentUser:
    if not user.is_admin:
        raise ApiError(403, "This action requires an administrator.")
    return user


def client_ip(request: Request) -> str:
    # Behind a reverse proxy, configure the server (uvicorn --proxy-headers) to set request.client.
    return request.client.host if request.client else "unknown"


def rate_limited(bucket: str, per_minute: Callable[[Settings], int], by: str = "ip") -> Callable:
    """Dependency factory: 429 when the caller exceeds `per_minute` requests in `bucket`."""
    def dependency(request: Request, settings: Settings = Depends(settings_dep)) -> None:
        who = getattr(request.state, "username", None) if by == "user" else None
        key = f"{bucket}:{who or client_ip(request)}"
        retry = limiter.hit(key, per_minute(settings))
        if retry is not None:
            raise ApiError(429, "Too many requests. Please wait and try again.",
                           headers={"Retry-After": str(int(retry) + 1)})
    return dependency
