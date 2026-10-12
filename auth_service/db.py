"""Database engine, session factory and ORM base for the authentication service."""
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from auth_service.config import AUTH_DATABASE_URL

engine = create_engine(
    AUTH_DATABASE_URL,
    connect_args=(
        {"check_same_thread": False}
        if AUTH_DATABASE_URL.startswith("sqlite")
        else {}
    ),
)
SessionLocal = sessionmaker(bind=engine, autoflush=False)


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """Consistently naive UTC timestamp (SQLite doesn't store tz info)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    import auth_service.models  # noqa: F401 – registers all models with Base
    Base.metadata.create_all(bind=engine)
