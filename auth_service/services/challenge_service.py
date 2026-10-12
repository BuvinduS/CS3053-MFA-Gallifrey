"""Challenge service – cryptographically secure nonce generation (mypart.md §3, BR-02).

The nonce is a base64url-encoded (no-padding) encoding of 32 random bytes.
It is generated fresh for every authentication transaction and every
enrollment challenge so that an old approval cannot be replayed (§10).
"""
import base64
import secrets


def generate_nonce() -> str:
    """Return a fresh 256-bit nonce as base64url without padding."""
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
