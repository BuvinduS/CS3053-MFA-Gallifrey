"""AuthAccount – an account registered with the authentication service.

The authentication service stores its own account reference (auth_account_id)
and an opaque RP subject string.  It never stores the RP password hash.
"""
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_service.db import Base


class AuthAccount(Base):
    __tablename__ = "auth_accounts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    # Opaque identifier supplied by the RP (e.g. the RP's internal user-id string).
    # Combined with rp_id it is unique.
    rp_subject: Mapped[str] = mapped_column(String(255))
    rp_id: Mapped[str] = mapped_column(ForeignKey("relying_parties.id"))
    created_at: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint("rp_id", "rp_subject", name="uq_rp_subject"),
    )

    devices: Mapped[list["RegisteredDevice"]] = relationship(  # noqa: F821
        back_populates="account", lazy="select"
    )
    transactions: Mapped[list["AuthTransaction"]] = relationship(  # noqa: F821
        back_populates="account", lazy="select"
    )
