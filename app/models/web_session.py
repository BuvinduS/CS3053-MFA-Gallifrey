from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class WebSession(Base):
    __tablename__ = "web_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Only the SHA-256 hash of the token is stored; the raw token lives only in the cookie.
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    authenticated_at: Mapped[datetime]
    expires_at: Mapped[datetime]
