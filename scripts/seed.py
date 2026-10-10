from sqlalchemy import select

from app.db import SessionLocal, init_db
from app.models import User
from app.services.user_service import hash_password

init_db()
with SessionLocal() as db:
    if db.scalar(select(User).where(User.username == "demo_user")) is None:
        db.add(User(username="demo_user",
               password_hash=hash_password("demo-password")))
        db.commit()
        print("Created demo_user / demo-password")
    else:
        print("demo_user already exists")
