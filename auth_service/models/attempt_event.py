"""AttemptEvent – a failed haptic-pattern attempt reported by the mobile app.

Idempotency: the client supplies a unique event_id (UUID).  The database
UNIQUE constraint on event_id prevents a retried delivery from incrementing
attempt_count twice (§12 – "unique device/event ID so retried delivery
cannot increment the count twice").

The raw expected or entered patterns are NEVER stored here (BR-06).
"""
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_service.db import Base


class AttemptEvent(Base):
    __tablename__ = "attempt_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    transaction_id: Mapped[str] = mapped_column(ForeignKey("auth_transactions.id"))
    # Client-generated UUID – unique so retried delivery doesn't double-count.
    event_id: Mapped[str] = mapped_column(String(36))
    device_id: Mapped[str] = mapped_column(ForeignKey("registered_devices.id"))
    created_at: Mapped[datetime]

    transaction: Mapped["AuthTransaction"] = relationship(  # noqa: F821
        back_populates="attempts"
    )

    __table_args__ = (
        UniqueConstraint("device_id", "event_id", name="uq_device_attempt_event"),
    )
