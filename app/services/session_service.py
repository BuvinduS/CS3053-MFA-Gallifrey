import hashlib
import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import utcnow
from app.models import User, WebSession

from fastapi import Response
from app.config import COOKIE_SECURE, SESSION_COOKIE_NAME, SESSION_TTL_MINUTES


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User) -> str:
    """Create a server-side session and return the raw token (for the cookie only)."""
    token = secrets.token_urlsafe(32)
    now = utcnow()
    db.add(WebSession(
        token_hash=_hash(token),
        user_id=user.id,
        authenticated_at=now,
        expires_at=now + timedelta(minutes=SESSION_TTL_MINUTES),
    ))
    db.commit()
    return token


def get_user_for_token(db: Session, token: str | None) -> User | None:
    if not token:
        return None
    ws = db.scalar(select(WebSession).where(
        WebSession.token_hash == _hash(token)))
    if ws is None or ws.expires_at <= utcnow():
        return None
    return db.get(User, ws.user_id)


def delete_session(db: Session, token: str | None) -> None:
    if not token:
        return
    ws = db.scalar(select(WebSession).where(
        WebSession.token_hash == _hash(token)))
    if ws:
        db.delete(ws)
        db.commit()


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        max_age=SESSION_TTL_MINUTES * 60,
        httponly=True, secure=COOKIE_SECURE, samesite="lax",
    )
