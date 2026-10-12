"""Short-lived, pseudonymized records used for authentication throttling."""
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from auth_service.db import Base


class AuthRequestEvent(Base):
    __tablename__ = "auth_request_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    rp_id: Mapped[str] = mapped_column(ForeignKey("relying_parties.id"))
    account_id: Mapped[str] = mapped_column(ForeignKey("auth_accounts.id"))
    source_ip_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime]

    __table_args__ = (
        Index("ix_auth_request_account_time", "rp_id", "account_id", "created_at"),
        Index("ix_auth_request_ip_time", "source_ip_hash", "created_at"),
    )
