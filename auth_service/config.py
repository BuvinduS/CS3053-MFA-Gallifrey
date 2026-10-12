"""Authentication service configuration.

All values can be overridden with environment variables.
"""
import os

# SQLite by default; use postgresql+psycopg://... for PostgreSQL.
AUTH_DATABASE_URL = os.getenv(
    "AUTH_DATABASE_URL", "sqlite:///./auth_service.db"
)

# 256-bit random secret shared with the RP.  The RP sends it; we store the
# hash.  Generate once and keep in environment / secrets manager.
RP_CLIENT_SECRET = os.getenv("RP_CLIENT_SECRET", "dev-rp-secret-change-me")

# Transaction expiry (seconds).  Design parameter D01.
AUTH_TX_TTL_SECONDS = int(os.getenv("AUTH_TX_TTL_SECONDS", "120"))

# Max failed haptic-pattern attempts before LOCKED.  Design parameter D02.
MAX_FAILURE_ATTEMPTS = int(os.getenv("MAX_FAILURE_ATTEMPTS", "3"))

# Authentication-request throttles (design defaults: 3/account and 10/IP per
# five minutes). IP addresses are stored only as keyed hashes.
AUTH_REQUEST_RATE_WINDOW_SECONDS = int(
    os.getenv("AUTH_REQUEST_RATE_WINDOW_SECONDS", "300")
)
MAX_AUTH_REQUESTS_PER_ACCOUNT = int(
    os.getenv("MAX_AUTH_REQUESTS_PER_ACCOUNT", "3")
)
MAX_AUTH_REQUESTS_PER_IP = int(os.getenv("MAX_AUTH_REQUESTS_PER_IP", "10"))
RATE_LIMIT_HMAC_KEY = os.getenv("RATE_LIMIT_HMAC_KEY", RP_CLIENT_SECRET)

# Result code TTL (seconds).  Design parameter D05.
RESULT_TTL_SECONDS = int(os.getenv("RESULT_TTL_SECONDS", "30"))

# Enrollment token TTL (seconds).
ENROLLMENT_TTL_SECONDS = int(os.getenv("ENROLLMENT_TTL_SECONDS", "300"))  # 5 min

# Audit-log retention (days) – informational; not enforced by this service yet.
AUDIT_RETENTION_DAYS = int(os.getenv("AUDIT_RETENTION_DAYS", "30"))

# Encrypt the short-lived recoverable result code used by the RP result route.
# Supply a random secret through the environment outside local development.
RESULT_ENCRYPTION_KEY = os.getenv(
    "RESULT_ENCRYPTION_KEY", "development-only-result-encryption-key"
)

if not 1 <= MAX_FAILURE_ATTEMPTS <= 3:
    raise ValueError("MAX_FAILURE_ATTEMPTS must be between 1 and 3")
if min(AUTH_TX_TTL_SECONDS, RESULT_TTL_SECONDS, ENROLLMENT_TTL_SECONDS) <= 0:
    raise ValueError("Transaction, result and enrollment TTLs must be positive")
if min(
    AUTH_REQUEST_RATE_WINDOW_SECONDS,
    MAX_AUTH_REQUESTS_PER_ACCOUNT,
    MAX_AUTH_REQUESTS_PER_IP,
) <= 0:
    raise ValueError("Authentication request rate limits must be positive")
