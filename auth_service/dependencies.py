"""FastAPI dependency providers for the authentication service."""
import hashlib

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth_service.db import get_db
from auth_service.models.registered_device import RegisteredDevice
from auth_service.models.relying_party import RelyingParty


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------------------
# RP authentication
# ---------------------------------------------------------------------------

def get_rp(
    authorization: str | None = Header(None, alias="Authorization"),
    db: Session = Depends(get_db),
) -> RelyingParty:
    """Verify the RP bearer credential.

    For the prototype a single shared secret is configured via env.
    Production would look up by client_id and compare the hashed secret.
    """
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    rp = db.scalar(
        select(RelyingParty).where(
            RelyingParty.client_secret_hash == _sha256(token),
            RelyingParty.status == "ACTIVE",
        )
    )
    if rp is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid RP credential")
    return rp


# ---------------------------------------------------------------------------
# Device token authentication
# ---------------------------------------------------------------------------

def get_device(
    authorization: str | None = Header(None, alias="Authorization"),
    db: Session = Depends(get_db),
) -> RegisteredDevice:
    """Verify the mobile device API token."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing device token")

    device = db.scalar(
        select(RegisteredDevice).where(
            RegisteredDevice.device_token_hash == _sha256(token),
        )
    )
    if device is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Invalid device token"
        )
    if device.status != "ACTIVE":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Device inactive")
    return device
