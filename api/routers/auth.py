"""Authentication: sign in, sign out, current user."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import CurrentUser, client_ip, current_user, get_db, rate_limited, settings_dep
from api.errors import ApiError
from api.security import authenticate, create_session, revoke_session
from core import audit
from core.config import Settings

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@router.post("/login", dependencies=[Depends(rate_limited("login", lambda s: s.login_rate_per_minute))])
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db),
          settings: Settings = Depends(settings_dep)):
    user = authenticate(db, body.username, body.password)
    if user is None:
        audit.record_event("LOGIN_FAILED", "anonymous", {"username": body.username[:64], "ip": client_ip(request)})
        raise ApiError(401, "Incorrect username or password.")
    token, expires = create_session(db, user, settings.session_ttl_minutes)
    db.commit()
    audit.record_event("USER_LOGIN", user.username, {"role": user.role, "ip": client_ip(request)})
    return {"access_token": token, "token_type": "bearer", "expires_at": expires.isoformat(),
            "user": {"username": user.username, "role": user.role}}


@router.post("/logout", status_code=204)
def logout(user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    session = db.merge(user.session)
    revoke_session(db, session)
    db.commit()


@router.get("/me")
def me(user: CurrentUser = Depends(current_user)):
    return {"username": user.username, "role": user.role}
