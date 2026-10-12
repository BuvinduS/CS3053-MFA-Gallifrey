"""AuthTransaction – the authoritative record of one second-factor request.

States (mypart.md §5):
  PENDING → APPROVED | DENIED | EXPIRED | LOCKED | CANCELLED

Terminal states: APPROVED, DENIED, EXPIRED, LOCKED, CANCELLED.
Once terminal, no further decision is accepted (replay prevention).

Fields:
  - challenge_nonce:  base64url-encoded 32 random bytes; fresh per request.
  - login_binding:    random per login attempt; never sent to the browser.
  - attempt_count:    [0, 3]; locked at 3 (D02).
  - fetched_at:       set when the device first retrieves the request (delivery
                      tracking separate from authentication state, §11).
"""
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_service.db import Base

TERMINAL_STATES = {"APPROVED", "DENIED", "EXPIRED", "LOCKED", "CANCELLED"}


class AuthTransaction(Base):
    __tablename__ = "auth_transactions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    account_id: Mapped[str] = mapped_column(ForeignKey("auth_accounts.id"))
    device_id: Mapped[str] = mapped_column(ForeignKey("registered_devices.id"))
    rp_id: Mapped[str] = mapped_column(ForeignKey("relying_parties.id"))
    # Cryptographic nonce – base64url, 32 bytes.
    challenge_nonce: Mapped[str] = mapped_column(String(64))
    # Random per login; RP binds this to a single browser session.
    login_binding: Mapped[str] = mapped_column(String(64))
    idempotency_key: Mapped[str | None] = mapped_column(String(128), default=None)
    # PENDING | APPROVED | DENIED | EXPIRED | LOCKED | CANCELLED
    status: Mapped[str] = mapped_column(String(16), default="PENDING")
    attempt_count: Mapped[int] = mapped_column(default=0)
    expires_at: Mapped[datetime]
    created_at: Mapped[datetime]
    fetched_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint("rp_id", "idempotency_key", name="uq_rp_idempotency_key"),
        CheckConstraint("attempt_count >= 0 AND attempt_count <= 3",
                        name="ck_attempt_count_range"),
        CheckConstraint(
            "status IN ('PENDING','APPROVED','DENIED','EXPIRED','LOCKED','CANCELLED')",
            name="ck_tx_status",
        ),
        CheckConstraint("expires_at > created_at", name="ck_expiry_after_creation"),
    )

    account: Mapped["AuthAccount"] = relationship(  # noqa: F821
        back_populates="transactions"
    )
    relying_party: Mapped["RelyingParty"] = relationship()  # noqa: F821
    device: Mapped["RegisteredDevice"] = relationship(  # noqa: F821
        back_populates="transactions"
    )
    attempts: Mapped[list["AttemptEvent"]] = relationship(  # noqa: F821
        back_populates="transaction", lazy="select"
    )
    result: Mapped["AuthResult | None"] = relationship(  # noqa: F821
        back_populates="transaction", uselist=False, lazy="select"
    )
