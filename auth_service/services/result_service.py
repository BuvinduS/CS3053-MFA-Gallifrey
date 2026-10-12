"""Issue, retrieve and consume short-lived RP result codes."""
import base64
import hashlib
import logging
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from auth_service.config import RESULT_ENCRYPTION_KEY
from auth_service.db import utcnow
from auth_service.models.audit_event import EVT_RESULT_INVALIDATED, EVT_RESULT_REDEEMED
from auth_service.models.auth_result import AuthResult
from auth_service.models.auth_transaction import AuthTransaction
from auth_service.models.registered_device import RegisteredDevice
from auth_service.services import audit_writer

logger = logging.getLogger(__name__)


class ResultError(Exception):
    pass


class ResultNotAvailable(ResultError):
    pass


class ResultAlreadyRedeemed(ResultError):
    pass


class ResultExpired(ResultError):
    pass


class ResultBindingMismatch(ResultError):
    pass


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _encryption_key() -> bytes:
    return hashlib.sha256(RESULT_ENCRYPTION_KEY.encode()).digest()


def encrypt_result_code(transaction_id: str, code: str) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_encryption_key()).encrypt(
        nonce, code.encode(), transaction_id.encode()
    )
    return base64.urlsafe_b64encode(nonce + ciphertext).rstrip(b"=").decode()


def _decrypt_result_code(result: AuthResult) -> str:
    encoded = result.code_ciphertext.encode()
    encoded += b"=" * (-len(encoded) % 4)
    payload = base64.b64decode(encoded, altchars=b"-_", validate=True)
    if len(payload) <= 12:
        raise ValueError("Malformed encrypted result")
    return AESGCM(_encryption_key()).decrypt(
        payload[:12], payload[12:], result.transaction_id.encode()
    ).decode()


def get_result_code(db: Session, transaction_id: str) -> str | None:
    """Return the same code to its authenticated RP until it is redeemed."""
    result = db.scalar(
        select(AuthResult).where(AuthResult.transaction_id == transaction_id)
    )
    if (
        result is None
        or result.redeemed_at is not None
        or result.invalidated_at is not None
    ):
        return None
    if utcnow() >= result.expires_at:
        if result.code_ciphertext:
            result.code_ciphertext = ""
            db.commit()
        return None
    try:
        return _decrypt_result_code(result)
    except Exception as exc:  # noqa: BLE001
        logger.error("Unable to decrypt result code for tx=%s (%s)",
                     transaction_id, type(exc).__name__)
        raise ResultNotAvailable("Result is unavailable") from exc


def invalidate_unredeemed_result(
    db: Session,
    *,
    transaction_id: str,
    actor: str,
) -> bool:
    """Invalidate an unredeemed result while the caller holds device/tx locks."""
    result = db.scalar(
        select(AuthResult)
        .where(AuthResult.transaction_id == transaction_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if (
        result is None
        or result.redeemed_at is not None
        or result.invalidated_at is not None
    ):
        return False

    now = utcnow()
    result.invalidated_at = now
    result.code_ciphertext = ""
    audit_writer.write(
        db,
        EVT_RESULT_INVALIDATED,
        transaction_id=transaction_id,
        actor=actor,
    )
    return True


def redeem_result(
    db: Session,
    *,
    result_code: str,
    login_binding: str,
    rp_id: str,
) -> AuthTransaction:
    """Consume the result once after checking its RP and browser binding."""
    code_hash = _hash(result_code)
    result_preview = db.scalar(
        select(AuthResult).where(AuthResult.code_hash == code_hash)
    )
    if result_preview is None:
        raise ResultNotAvailable("Unknown result code")

    tx_preview = db.get(AuthTransaction, result_preview.transaction_id)
    if tx_preview is None:
        raise ResultNotAvailable("Authentication request unavailable")
    device = db.scalar(
        select(RegisteredDevice)
        .where(RegisteredDevice.id == tx_preview.device_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if device is None or device.status != "ACTIVE":
        raise ResultNotAvailable("Device is inactive")
    tx = db.scalar(
        select(AuthTransaction)
        .where(AuthTransaction.id == tx_preview.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if tx is None or tx.rp_id != rp_id:
        raise ResultBindingMismatch("RP / transaction mismatch")
    if tx.status != "APPROVED":
        raise ResultNotAvailable("Authentication request is not approved")
    result = db.scalar(
        select(AuthResult)
        .where(AuthResult.id == result_preview.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if result is None or result.invalidated_at is not None:
        raise ResultNotAvailable("Result is no longer available")
    if result.redeemed_at is not None:
        raise ResultAlreadyRedeemed("Result already redeemed")

    now = utcnow()
    if now >= result.expires_at:
        result.code_ciphertext = ""
        db.commit()
        raise ResultExpired("Result code expired")
    if not secrets.compare_digest(result.login_binding, login_binding):
        raise ResultBindingMismatch("login_binding mismatch")

    redeemed = db.execute(
        update(AuthResult)
        .where(
            AuthResult.id == result.id,
            AuthResult.redeemed_at.is_(None),
            AuthResult.invalidated_at.is_(None),
            AuthResult.expires_at > now,
        )
        .values(redeemed_at=now, code_ciphertext="")
        .execution_options(synchronize_session=False)
    )
    if redeemed.rowcount != 1:
        db.rollback()
        current = db.get(AuthResult, result.id)
        if current is not None and current.redeemed_at is not None:
            raise ResultAlreadyRedeemed("Result already redeemed")
        if current is not None and current.invalidated_at is not None:
            raise ResultNotAvailable("Result is no longer available")
        raise ResultExpired("Result code expired")

    audit_writer.write(
        db,
        EVT_RESULT_REDEEMED,
        transaction_id=tx.id,
        actor=rp_id,
    )
    db.commit()
    return tx
