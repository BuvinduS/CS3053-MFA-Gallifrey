import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./gallifrey.db")

SESSION_COOKIE_NAME = "gallifrey_session"
SESSION_TTL_MINUTES = 30

PENDING_LOGIN_TTL_SECONDS = 120   # demo expiry
PENDING_COOKIE_NAME = "gallifrey_pending"

# Secure by default. Only override for local HTTP development:
#   COOKIE_SECURE=false uvicorn app.main:app --reload
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"
