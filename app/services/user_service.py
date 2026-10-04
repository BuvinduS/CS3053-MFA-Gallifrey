from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User

_hasher = PasswordHasher()
# Used so a missing user costs the same time as a wrong password.
_DUMMY_HASH = _hasher.hash("dummy-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def authenticate(db: Session, username: str, password: str) -> User | None:
    """First factor only. Returns the User if the password is valid, else None."""
    user = db.scalar(select(User).where(User.username == username))
    try:
        _hasher.verify(user.password_hash if user else _DUMMY_HASH, password)
    except VerificationError:
        return None
    # None if user didn't exist (dummy hash can't match a real password)
    return user
