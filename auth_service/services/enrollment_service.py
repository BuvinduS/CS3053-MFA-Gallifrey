"""Enrollment service – device key onboarding (mypart.md §8, design §8).

Flow:
  POST /v1/enrollments            – RP creates token (5 min)
  POST /v1/enrollments/claim      – Mobile submits public key → provisional device
  POST /v1/enrollments/{id}/complete – Mobile signs challenge → device activated
"""
import base64
import hashlib
import secrets
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from auth_service.config import ENROLLMENT_TTL_SECONDS
from auth_service.db import utcnow
from auth_service.models.audit_event import (
    EVT_ENROLLMENT_COMPLETED,
    EVT_ENROLLMENT_STARTED,
    EVT_DEVICE_REVOKED,
    EVT_TRANSACTION_CANCELLED,
)
from auth_service.models.auth_account import AuthAccount
from auth_service.models.enrollment import Enrollment
from auth_service.models.registered_device import RegisteredDevice
from auth_service.models.auth_transaction import AuthTransaction
from auth_service.services import audit_writer, challenge_service, result_service, signature_service

class EnrollmentError(Exception):
    pass


class EnrollmentNotFound(EnrollmentError):
    pass


class EnrollmentTokenInvalid(EnrollmentError):
    """Token missing, expired, already claimed, or already completed."""


class EnrollmentProofInvalid(EnrollmentError):
    pass


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _decode_b64url(value: str) -> bytes:
    if not value or len(value) > 2048:
        raise ValueError("Invalid base64url length")
    padded = value + "=" * (-len(value) % 4)
    decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ValueError("Non-canonical base64url value")
    return decoded


def _fingerprint(spki_b64url: str) -> str:
    raw = _decode_b64url(spki_b64url)
    return hashlib.sha256(raw).hexdigest()


def fingerprint_b64url(spki_b64url: str) -> str:
    raw = _decode_b64url(spki_b64url)
    digest = hashlib.sha256(raw).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _validate_p256_spki(spki_b64url: str) -> ec.EllipticCurvePublicKey:
    """Load and validate that the key is a P-256 EC public key."""
    try:
        raw = _decode_b64url(spki_b64url)
        key = serialization.load_der_public_key(raw)
    except Exception as exc:  # noqa: BLE001
        raise EnrollmentError("Invalid public key encoding") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise EnrollmentError("Not an EC public key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise EnrollmentError("Public key is not P-256")
    return key


# ---------------------------------------------------------------------------
# Step 1 – RP requests enrollment token
# ---------------------------------------------------------------------------

def create_enrollment_token(
    db: Session,
    *,
    rp_id: str,
    account_id: str,
) -> str:
    """Create a 5-minute enrollment token bound to the account; return the raw token."""
    raw_token = secrets.token_urlsafe(32)
    now = utcnow()
    enrollment = Enrollment(
        account_id=account_id,
        rp_id=rp_id,
        token_hash=_hash_token(raw_token),
        status="PENDING",
        expires_at=now + timedelta(seconds=ENROLLMENT_TTL_SECONDS),
        created_at=now,
    )
    db.add(enrollment)
    audit_writer.write(
        db, EVT_ENROLLMENT_STARTED,
        actor=rp_id,
        metadata={"account_id": account_id},
    )
    db.commit()
    return raw_token  # returned to RP once; never stored raw


# ---------------------------------------------------------------------------
# Step 2 – Mobile claims token, submits public key
# ---------------------------------------------------------------------------

def claim_enrollment(
    db: Session,
    *,
    enrollment_token: str,
    public_key_spki_b64url: str,
) -> tuple[Enrollment, str, RegisteredDevice]:  # enrollment, nonce and provisional device
    """Validate token, create provisional device, return enrollment challenge."""
    token_hash = _hash_token(enrollment_token)
    enrollment = db.scalar(
        select(Enrollment)
        .where(Enrollment.token_hash == token_hash)
        .with_for_update()
    )
    if enrollment is None:
        raise EnrollmentTokenInvalid("Unknown token")
    if enrollment.status != "PENDING":
        raise EnrollmentTokenInvalid(f"Token already {enrollment.status}")
    if utcnow() >= enrollment.expires_at:
        enrollment.status = "EXPIRED"
        db.commit()
        raise EnrollmentTokenInvalid("Token expired")

    # Validate the public key.
    _validate_p256_spki(public_key_spki_b64url)

    # Create a provisional (inactive until step 3) device.
    device = RegisteredDevice(
        account_id=enrollment.account_id,
        public_key_spki=public_key_spki_b64url,
        key_fingerprint=_fingerprint(public_key_spki_b64url),
        status="PROVISIONAL",  # not yet active
        registered_at=utcnow(),
    )
    db.add(device)
    db.flush()

    # Generate the possession-proof challenge.
    challenge_nonce = challenge_service.generate_nonce()
    claimed = db.execute(
        update(Enrollment)
        .where(
            Enrollment.id == enrollment.id,
            Enrollment.status == "PENDING",
            Enrollment.expires_at > utcnow(),
        )
        .values(
            status="CLAIMED",
            device_id=device.id,
            challenge=challenge_nonce,
        )
        .execution_options(synchronize_session=False)
    )
    if claimed.rowcount != 1:
        db.rollback()
        raise EnrollmentTokenInvalid("Token already claimed or expired")
    db.commit()
    db.refresh(enrollment)

    # Return provisional device id and challenge (not the raw device token yet).
    return enrollment, challenge_nonce, device


# ---------------------------------------------------------------------------
# Step 3 – Mobile signs challenge → device activated
# ---------------------------------------------------------------------------

def complete_enrollment(
    db: Session,
    *,
    enrollment_id: str,
    signature_b64url: str,
) -> tuple[RegisteredDevice, str]:  # (device, raw_device_api_token)
    """Verify proof of key possession; activate device; return the scoped API token."""
    enrollment = db.scalar(
        select(Enrollment)
        .where(Enrollment.id == enrollment_id)
        .with_for_update()
    )
    if enrollment is None or enrollment.status != "CLAIMED":
        raise EnrollmentNotFound(enrollment_id)
    if utcnow() >= enrollment.expires_at:
        enrollment.status = "EXPIRED"
        db.commit()
        raise EnrollmentTokenInvalid("Enrollment expired")

    device = db.get(RegisteredDevice, enrollment.device_id)
    if device is None or device.status != "PROVISIONAL":
        raise EnrollmentError("Provisional device missing")

    valid_proof = signature_service.verify_enrollment_signature(
        public_key_spki_b64url=device.public_key_spki,
        signature_b64url=signature_b64url,
        enrollment_id=enrollment.id,
        enrollment_nonce=enrollment.challenge,
        account_ref=enrollment.account_id,
        device_id=device.id,
        public_key_fingerprint=fingerprint_b64url(device.public_key_spki),
    )
    if not valid_proof:
        raise EnrollmentProofInvalid("Enrollment signature invalid")

    # Revoke any previous ACTIVE device for this account (device replacement).
    old_active = db.scalar(
        select(RegisteredDevice).where(
            RegisteredDevice.account_id == device.account_id,
            RegisteredDevice.status == "ACTIVE",
        ).with_for_update()
    )
    if old_active is not None:
        old_active.status = "REVOKED"
        old_active.revoked_at = utcnow()
        audit_writer.write(
            db,
            EVT_DEVICE_REVOKED,
            actor=device.id,
            metadata={"device_id": old_active.id},
        )
        device_transactions = db.scalars(
            select(AuthTransaction)
            .where(AuthTransaction.device_id == old_active.id)
            .order_by(AuthTransaction.id)
            .with_for_update()
        ).all()
        now = utcnow()
        for tx in device_transactions:
            if tx.status == "PENDING":
                tx.status = "CANCELLED"
                tx.completed_at = now
                audit_writer.write(
                    db,
                    EVT_TRANSACTION_CANCELLED,
                    transaction_id=tx.id,
                    actor=device.id,
                )
            result_service.invalidate_unredeemed_result(
                db, transaction_id=tx.id, actor=device.id
            )

    # Activate the new device and issue a fresh scoped API token.
    new_token_raw = secrets.token_urlsafe(32)
    device.status = "ACTIVE"
    device.device_token_hash = _hash_token(new_token_raw)

    enrollment.status = "COMPLETED"
    enrollment.completed_at = utcnow()

    audit_writer.write(
        db,
        EVT_ENROLLMENT_COMPLETED,
        actor=device.id,
        metadata={"account_id": device.account_id},
    )
    db.commit()

    return device, new_token_raw  # caller returns raw token once; we store only hash
