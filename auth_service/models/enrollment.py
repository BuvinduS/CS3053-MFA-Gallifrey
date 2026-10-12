"""Enrollment – temporary record for device onboarding (§8).

Lifecycle:
  1. RP creates an enrollment token (5-minute expiry).
  2. Mobile app claims the token → provisional device record created,
     enrollment challenge issued.
  3. Mobile app signs the challenge → device activated, token consumed.

Only the hash of the enrollment token is stored; the raw bearer token
is returned to the RP once and never persisted (same as result codes).
"""
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from auth_service.db import Base


class Enrollment(Base):
    __tablename__ = "enrollments"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    account_id: Mapped[str] = mapped_column(ForeignKey("auth_accounts.id"))
    rp_id: Mapped[str] = mapped_column(ForeignKey("relying_parties.id"))
    # SHA-256 hex of the enrollment token bearer secret.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # Set once the mobile app claims the token (provisional device).
    device_id: Mapped[str | None] = mapped_column(
        ForeignKey("registered_devices.id"), default=None
    )
    # The challenge the app must sign to prove key possession.
    challenge: Mapped[str | None] = mapped_column(String(64), default=None)
    # PENDING | CLAIMED | COMPLETED | EXPIRED
    status: Mapped[str] = mapped_column(String(16), default="PENDING")
    expires_at: Mapped[datetime]
    created_at: Mapped[datetime]
    completed_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','CLAIMED','COMPLETED','EXPIRED')",
            name="ck_enrollment_status",
        ),
        CheckConstraint("expires_at > created_at", name="ck_enrollment_expiry"),
    )
