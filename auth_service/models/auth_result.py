"""AuthResult – the one-time result code issued after APPROVED.

Security properties (§12):
  - code_hash: SHA-256 of the raw one-time result code.
  - code_ciphertext: short-lived AES-GCM copy for safe RP retries.
  - redeemed_at: set once on successful redemption.  A second redemption
    attempt is rejected (one-time use, §11).
  - login_binding: stored here for cross-checking at redemption time.
  - expires_at: the result code expires independently (D05: 30 seconds).
"""
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_service.db import Base


class AuthResult(Base):
    __tablename__ = "auth_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    transaction_id: Mapped[str] = mapped_column(
        ForeignKey("auth_transactions.id"), unique=True
    )
    # Hex SHA-256 of the raw one-time result code.
    code_hash: Mapped[str] = mapped_column(String(64))
    # Base64url(nonce || AES-GCM ciphertext), encrypted with a server-only key.
    code_ciphertext: Mapped[str] = mapped_column(String(256))
    login_binding: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime]
    created_at: Mapped[datetime]
    redeemed_at: Mapped[datetime | None] = mapped_column(default=None)
    invalidated_at: Mapped[datetime | None] = mapped_column(default=None)

    transaction: Mapped["AuthTransaction"] = relationship(  # noqa: F821
        back_populates="result"
    )
