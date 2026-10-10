import hashlib
import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import PENDING_LOGIN_TTL_SECONDS
from app.db import utcnow
from app.models import PendingLogin, User
from app.services.auth_service_client import AuthServiceClient


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_pending_login(db: Session, user: User, auth_client: AuthServiceClient) -> str:
    """Ask the auth service for an MFA request, record a PendingLogin, return the cookie token.

    Raises AuthServiceError if the service can't create the request; in that case
    nothing is stored and no cookie is issued.
    """
    login_binding = secrets.token_urlsafe(32)  # fresh for every login attempt
    # The binding goes to the auth service; the browser never sees it.
    tx_id = auth_client.create_request(
        account_id=str(user.id), login_binding=login_binding)

    token = secrets.token_urlsafe(32)
    now = utcnow()
    db.add(PendingLogin(
        token_hash=_hash(token),
        user_id=user.id,
        auth_tx_id=tx_id,
        login_binding=login_binding,
        created_at=now,
        expires_at=now + timedelta(seconds=PENDING_LOGIN_TTL_SECONDS),
        status="PENDING",
    ))
    db.commit()
    return token


def get_active_pending_login(db: Session, token: str | None) -> PendingLogin | None:
    """Return the PendingLogin for this cookie if it exists, is PENDING and unexpired."""
    if not token:
        return None
    pl = db.scalar(select(PendingLogin).where(
        PendingLogin.token_hash == _hash(token)))
    if pl is None or pl.status != "PENDING" or pl.expires_at <= utcnow():
        return None
    return pl
