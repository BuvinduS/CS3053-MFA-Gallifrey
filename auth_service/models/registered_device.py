"""RegisteredDevice – binds a device public key to an AuthAccount.

Security constraints (mypart.md §6):
  - public_key_spki is required and unique (one key per device record).
  - device_token_hash stores the SHA-256 of the scoped API token; the raw
    token is only ever returned once at enrollment completion.
  - A partial unique index (status='ACTIVE') enforces one active device per
    account (A06).  Additional INACTIVE / REVOKED records are kept for audit.
  - revoked_at is set when the device is revoked; key_fingerprint is the
    SHA-256 of the DER public key bytes (for log / audit references).
"""
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_service.db import Base


class RegisteredDevice(Base):
    __tablename__ = "registered_devices"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    account_id: Mapped[str] = mapped_column(ForeignKey("auth_accounts.id"))
    # DER SubjectPublicKeyInfo encoded as base64url (no padding).
    public_key_spki: Mapped[str] = mapped_column(String(512), unique=True)
    # Hex SHA-256 of the raw DER bytes – for log references; never the private key.
    key_fingerprint: Mapped[str] = mapped_column(String(64))
    # SHA-256 of the scoped random device API token (256-bit raw, base64url).
    device_token_hash: Mapped[str | None] = mapped_column(
        String(64), unique=True, default=None
    )
    # PROVISIONAL | ACTIVE | REVOKED
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    registered_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)

    account: Mapped["AuthAccount"] = relationship(  # noqa: F821
        back_populates="devices"
    )
    transactions: Mapped[list["AuthTransaction"]] = relationship(  # noqa: F821
        back_populates="device", lazy="select"
    )

    # Partial unique index: at most one ACTIVE device per account.
    __table_args__ = (
        Index(
            "uq_one_active_device_per_account",
            "account_id",
            unique=True,
            sqlite_where=text("status = 'ACTIVE'"),
            postgresql_where=text("status = 'ACTIVE'"),
        ),
        CheckConstraint(
            "status IN ('PROVISIONAL','ACTIVE','REVOKED')",
            name="ck_device_status",
        ),
    )
