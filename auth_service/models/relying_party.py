"""RelyingParty – an authorized third-party application (RP) that can request MFA."""
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from auth_service.db import Base


class RelyingParty(Base):
    __tablename__ = "relying_parties"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(128))
    # Hash of the 256-bit bearer credential the RP uses for backend calls.
    client_secret_hash: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    created_at: Mapped[datetime]

    __table_args__ = (
        CheckConstraint("status IN ('ACTIVE','REVOKED')", name="ck_rp_status"),
    )
