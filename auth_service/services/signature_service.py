"""Signature verification service (mypart.md §3, §9, §10).

Protocol (Gallifrey_Unified_Design.md §10):
  Algorithm : ECDSA P-256 / SHA-256
  Public key: DER SubjectPublicKeyInfo, base64url no-padding
  Signature : ASN.1 DER, base64url no-padding

Signed message (exact bytes, LF-separated, no trailing newline):
  GALLIFREY-MFA-DECISION-V1
  transaction_id
  challenge_nonce
  account_id
  device_id
  rp_id
  login_binding
  APPROVE or DENY
  expires_at   (decimal Unix seconds)

Any deviation from this canonical form is rejected (no partial matches).
"""
import base64
import logging
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

_VERSION_PREFIX = "GALLIFREY-MFA-DECISION-V1"
_ENROLLMENT_VERSION_PREFIX = "GALLIFREY-MFA-ENROLL-V1"
_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_TOKEN_PATTERN = re.compile(r"^[!-~]{1,128}$")


def _decode_b64url(value: str) -> bytes:
    """Decode canonical, unpadded base64url protocol values."""
    if not value or len(value) > 2048:
        raise ValueError("Invalid base64url length")
    padded = value + "=" * (-len(value) % 4)
    decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ValueError("Non-canonical base64url value")
    return decoded


def _load_public_key(public_key_spki_b64url: str) -> ec.EllipticCurvePublicKey:
    """Load an ECDSA P-256 public key from a base64url DER SPKI blob."""
    der = _decode_b64url(public_key_spki_b64url)
    key = serialization.load_der_public_key(der)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("Public key is not an EC key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Public key curve is not P-256")
    return key


def _require_uuid(value: str, name: str) -> None:
    if not _UUID_PATTERN.fullmatch(value):
        raise ValueError(f"{name} must be a lower-case canonical UUID")


def _require_nonce(value: str, name: str) -> None:
    if len(_decode_b64url(value)) != 32:
        raise ValueError(f"{name} must encode 32 bytes")


def _require_token(value: str, name: str) -> None:
    if not _TOKEN_PATTERN.fullmatch(value):
        raise ValueError(f"{name} must be printable ASCII without whitespace")


def build_signed_message(
    *,
    transaction_id: str,
    challenge_nonce: str,
    account_id: str,
    device_id: str,
    rp_id: str,
    login_binding: str,
    decision: str,      # "APPROVE" or "DENY"
    expires_at_unix: int,
) -> bytes:
    """Reconstruct the exact byte string the Android app should have signed."""
    _require_uuid(transaction_id, "transaction_id")
    _require_nonce(challenge_nonce, "challenge_nonce")
    _require_uuid(account_id, "account_id")
    _require_uuid(device_id, "device_id")
    _require_token(rp_id, "rp_id")
    _require_token(login_binding, "login_binding")
    if expires_at_unix <= 0:
        raise ValueError("expires_at must be positive")

    parts = [
        _VERSION_PREFIX,
        transaction_id,
        challenge_nonce,
        account_id,
        device_id,
        rp_id,
        login_binding,
        decision,
        str(expires_at_unix),
    ]
    if decision not in {"APPROVE", "DENY"}:
        raise ValueError("Unsupported decision")
    return "\n".join(parts).encode("ascii")


def build_enrollment_message(
    *,
    enrollment_id: str,
    enrollment_nonce: str,
    account_ref: str,
    device_id: str,
    public_key_fingerprint: str,
) -> bytes:
    """Build the exact V1 enrollment proof bytes used by the Android client."""
    _require_uuid(enrollment_id, "enrollment_id")
    _require_nonce(enrollment_nonce, "enrollment_nonce")
    _require_token(account_ref, "account_ref")
    _require_uuid(device_id, "device_id")
    if len(_decode_b64url(public_key_fingerprint)) != 32:
        raise ValueError("public_key_fingerprint must encode a SHA-256 digest")

    return "\n".join(
        [
            _ENROLLMENT_VERSION_PREFIX,
            enrollment_id,
            enrollment_nonce,
            account_ref,
            device_id,
            public_key_fingerprint,
        ]
    ).encode("ascii")


def verify_decision(
    *,
    public_key_spki_b64url: str,
    signature_b64url: str,
    transaction_id: str,
    challenge_nonce: str,
    account_id: str,
    device_id: str,
    rp_id: str,
    login_binding: str,
    decision: str,
    expires_at_unix: int,
) -> bool:
    """Return True iff the signature is valid for the canonical message.

    Never raises on signature failure – returns False and logs a sanitized
    diagnostic (no private data).
    """
    try:
        key = _load_public_key(public_key_spki_b64url)
        message = build_signed_message(
            transaction_id=transaction_id,
            challenge_nonce=challenge_nonce,
            account_id=account_id,
            device_id=device_id,
            rp_id=rp_id,
            login_binding=login_binding,
            decision=decision,
            expires_at_unix=expires_at_unix,
        )
        sig_der = _decode_b64url(signature_b64url)
        key.verify(sig_der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        logger.info("Signature verification failed for tx=%s", transaction_id)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Signature verification error for tx=%s: %s", transaction_id, type(exc).__name__
        )
        return False


def verify_enrollment_signature(
    *,
    public_key_spki_b64url: str,
    signature_b64url: str,
    enrollment_id: str,
    enrollment_nonce: str,
    account_ref: str,
    device_id: str,
    public_key_fingerprint: str,
) -> bool:
    """Return True iff the V1 enrollment proof matches its canonical context."""
    try:
        key = _load_public_key(public_key_spki_b64url)
        message = build_enrollment_message(
            enrollment_id=enrollment_id,
            enrollment_nonce=enrollment_nonce,
            account_ref=account_ref,
            device_id=device_id,
            public_key_fingerprint=public_key_fingerprint,
        )
        key.verify(
            _decode_b64url(signature_b64url), message, ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        logger.info("Enrollment signature verification failed for enrollment=%s", enrollment_id)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Enrollment signature verification error for enrollment=%s: %s",
            enrollment_id,
            type(exc).__name__,
        )
        return False
