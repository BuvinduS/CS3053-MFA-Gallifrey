from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class PendingLogin(Base):
    """Website-side record: this browser passed the password and awaits MFA.

    Browser login -> PendingLogin -> authentication transaction (auth_tx_id)
    """
    __tablename__ = "pending_logins"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Hash of the opaque cookie token that identifies this browser's attempt.
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    # Filled in once the auth service creates the MFA request (Stage 3).
    auth_tx_id: Mapped[str | None] = mapped_column(String(64), default=None)
    # Random per login attempt. Never sent to the browser.
    login_binding: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    status: Mapped[str] = mapped_column(String(16), default="PENDING")
