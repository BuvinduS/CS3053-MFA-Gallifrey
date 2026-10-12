"""AuditEvent – sanitized security log (mypart.md §11).

What IS recorded: transaction references, event type, result, server time,
device_id, actor.

What is NEVER recorded: raw haptic patterns, passwords/hashes, private keys,
access/refresh tokens.
"""
import uuid
from datetime import datetime

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from auth_service.db import Base

# Canonical event type constants (§11).
EVT_AUTH_REQUEST_CREATED = "AUTH_REQUEST_CREATED"
EVT_AUTH_REQUEST_RATE_LIMITED = "AUTH_REQUEST_RATE_LIMITED"
EVT_REQUEST_FETCHED = "REQUEST_FETCHED"
EVT_FAILED_PATTERN_ATTEMPT = "FAILED_PATTERN_ATTEMPT"
EVT_APPROVAL_VERIFIED = "APPROVAL_VERIFIED"
EVT_USER_DENIED = "USER_DENIED"
EVT_TRANSACTION_EXPIRED = "TRANSACTION_EXPIRED"
EVT_TRANSACTION_LOCKED = "TRANSACTION_LOCKED"
EVT_INVALID_SIGNATURE = "INVALID_SIGNATURE"
EVT_DEVICE_REVOKED = "DEVICE_REVOKED"
EVT_ENROLLMENT_STARTED = "ENROLLMENT_STARTED"
EVT_ENROLLMENT_COMPLETED = "ENROLLMENT_COMPLETED"
EVT_RESULT_ISSUED = "RESULT_ISSUED"
EVT_RESULT_REDEEMED = "RESULT_REDEEMED"
EVT_RESULT_INVALIDATED = "RESULT_INVALIDATED"
EVT_TRANSACTION_CANCELLED = "TRANSACTION_CANCELLED"
EVT_RECOVERY_STARTED = "RECOVERY_STARTED"


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    # Optional FK – may be null for enrollment / device-level events.
    transaction_id: Mapped[str | None] = mapped_column(String(36), default=None)
    event_type: Mapped[str] = mapped_column(String(64))
    # device_id or rp_id or "system" – never a raw token.
    actor: Mapped[str | None] = mapped_column(String(64), default=None)
    # Minimal diagnostic context (no secrets).
    metadata_json: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime]
