"""Create and enforce the authoritative authentication transaction lifecycle."""
import calendar
import hashlib
import hmac
import math
import re
import secrets
from datetime import timedelta

from sqlalchemy import case, delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth_service.config import (
    AUTH_REQUEST_RATE_WINDOW_SECONDS,
    AUTH_TX_TTL_SECONDS,
    MAX_AUTH_REQUESTS_PER_ACCOUNT,
    MAX_AUTH_REQUESTS_PER_IP,
    MAX_FAILURE_ATTEMPTS,
    RATE_LIMIT_HMAC_KEY,
    RESULT_TTL_SECONDS,
)
from auth_service.db import utcnow
from auth_service.models.audit_event import (
    EVT_APPROVAL_VERIFIED,
    EVT_AUTH_REQUEST_CREATED,
    EVT_AUTH_REQUEST_RATE_LIMITED,
    EVT_FAILED_PATTERN_ATTEMPT,
    EVT_INVALID_SIGNATURE,
    EVT_REQUEST_FETCHED,
    EVT_RESULT_ISSUED,
    EVT_TRANSACTION_EXPIRED,
    EVT_TRANSACTION_LOCKED,
    EVT_USER_DENIED,
)
from auth_service.models.auth_account import AuthAccount
from auth_service.models.auth_request_event import AuthRequestEvent
from auth_service.models.auth_result import AuthResult
from auth_service.models.auth_transaction import AuthTransaction, TERMINAL_STATES
from auth_service.models.attempt_event import AttemptEvent
from auth_service.models.registered_device import RegisteredDevice
from auth_service.models.relying_party import RelyingParty
from auth_service.services import audit_writer, challenge_service, result_service, signature_service


class TransactionError(Exception):
    """Base for transaction-level errors (mapped to HTTP errors)."""


class TransactionNotFound(TransactionError):
    pass


class TransactionTerminal(TransactionError):
    """The request is already in a terminal state."""


class TransactionExpired(TransactionError):
    pass


class TransactionLocked(TransactionError):
    pass


class DeviceRevoked(TransactionError):
    pass


class SignatureInvalid(TransactionError):
    pass


class InvalidDecision(TransactionError):
    pass


class DuplicateAttemptEvent(TransactionError):
    """The device event was already processed and must not count again."""


class IdempotencyKeyConflict(TransactionError):
    """An RP reused an idempotency key for a different login attempt."""


class RequestRateLimited(TransactionError):
    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__("Authentication request rate limit exceeded")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hash_source_ip(source_ip: str | None) -> str | None:
    """Return a keyed pseudonym; never persist a raw client IP address."""
    if source_ip is None:
        return None
    return hmac.new(
        RATE_LIMIT_HMAC_KEY.encode(), source_ip.encode(), hashlib.sha256
    ).hexdigest()


def _limit_retry_after(
    db: Session,
    *,
    rp_id: str,
    now,
    scope: str,
    account_id: str | None = None,
    source_ip_hash: str | None = None,
) -> int:
    query = select(func.min(AuthRequestEvent.created_at)).where(
        AuthRequestEvent.created_at >= now - timedelta(
            seconds=AUTH_REQUEST_RATE_WINDOW_SECONDS
        ),
    )
    if scope == "account":
        query = query.where(
            AuthRequestEvent.account_id == account_id,
            AuthRequestEvent.rp_id == rp_id,
        )
    else:
        query = query.where(AuthRequestEvent.source_ip_hash == source_ip_hash)
    oldest = db.scalar(query)
    if oldest is None:
        return AUTH_REQUEST_RATE_WINDOW_SECONDS
    return max(
        1,
        math.ceil(
            (oldest + timedelta(seconds=AUTH_REQUEST_RATE_WINDOW_SECONDS) - now)
            .total_seconds()
        ),
    )


def _enforce_auth_request_limits(
    db: Session,
    *,
    rp_id: str,
    account_id: str,
    source_ip_hash: str | None,
    now,
) -> None:
    cutoff = now - timedelta(seconds=AUTH_REQUEST_RATE_WINDOW_SECONDS)
    db.execute(delete(AuthRequestEvent).where(AuthRequestEvent.created_at < cutoff))

    account_count = db.scalar(
        select(func.count(AuthRequestEvent.id)).where(
            AuthRequestEvent.rp_id == rp_id,
            AuthRequestEvent.account_id == account_id,
            AuthRequestEvent.created_at >= cutoff,
        )
    )
    if account_count >= MAX_AUTH_REQUESTS_PER_ACCOUNT:
        retry_after = _limit_retry_after(
            db, rp_id=rp_id, now=now, scope="account", account_id=account_id
        )
        audit_writer.write(
            db,
            EVT_AUTH_REQUEST_RATE_LIMITED,
            actor=rp_id,
            metadata={"account_id": account_id, "scope": "account"},
        )
        db.commit()
        raise RequestRateLimited(retry_after)

    if source_ip_hash is not None:
        ip_count = db.scalar(
            select(func.count(AuthRequestEvent.id)).where(
                AuthRequestEvent.source_ip_hash == source_ip_hash,
                AuthRequestEvent.created_at >= cutoff,
            )
        )
        if ip_count >= MAX_AUTH_REQUESTS_PER_IP:
            retry_after = _limit_retry_after(
                db,
                rp_id=rp_id,
                now=now,
                scope="ip",
                source_ip_hash=source_ip_hash,
            )
            audit_writer.write(
                db,
                EVT_AUTH_REQUEST_RATE_LIMITED,
                actor=rp_id,
                metadata={"account_id": account_id, "scope": "ip"},
            )
            db.commit()
            raise RequestRateLimited(retry_after)

    db.add(AuthRequestEvent(
        rp_id=rp_id,
        account_id=account_id,
        source_ip_hash=source_ip_hash,
        created_at=now,
    ))


def _expire_if_needed(
    db: Session, tx: AuthTransaction, *, actor: str | None = None
) -> AuthTransaction:
    """Atomically expire a pending request and persist its audit event."""
    now = utcnow()
    if tx.status == "PENDING" and now >= tx.expires_at:
        changed = db.execute(
            update(AuthTransaction)
            .where(
                AuthTransaction.id == tx.id,
                AuthTransaction.status == "PENDING",
                AuthTransaction.expires_at <= now,
            )
            .values(status="EXPIRED", completed_at=now)
            .execution_options(synchronize_session=False)
        )
        if changed.rowcount:
            audit_writer.write(
                db,
                EVT_TRANSACTION_EXPIRED,
                transaction_id=tx.id,
                actor=actor or "system",
            )
            db.commit()
        db.refresh(tx)
    return tx


def _lock_device_then_transaction(
    db: Session, *, device_id: str, transaction_id: str
) -> tuple[RegisteredDevice, AuthTransaction]:
    """Lock rows in the same device-then-transaction order as revocation."""
    device = db.scalar(
        select(RegisteredDevice)
        .where(RegisteredDevice.id == device_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if device is None:
        raise DeviceRevoked(device_id)

    tx = db.scalar(
        select(AuthTransaction)
        .where(AuthTransaction.id == transaction_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if tx is None:
        raise TransactionNotFound(transaction_id)
    if tx.device_id != device.id or tx.account_id != device.account_id:
        raise DeviceRevoked(device_id)
    return device, tx


def _raise_current_state(db: Session, transaction_id: str) -> None:
    """Translate a failed conditional transition to the current state error."""
    db.rollback()
    tx = db.get(AuthTransaction, transaction_id)
    if tx is None:
        raise TransactionNotFound(transaction_id)
    tx = _expire_if_needed(db, tx)
    if tx.status == "EXPIRED":
        raise TransactionExpired(transaction_id)
    if tx.status == "LOCKED":
        raise TransactionLocked(transaction_id)
    if tx.status in TERMINAL_STATES:
        raise TransactionTerminal(tx.status)
    if tx.attempt_count >= MAX_FAILURE_ATTEMPTS:
        raise TransactionLocked(transaction_id)
    raise TransactionTerminal(tx.status)


def create_transaction(
    db: Session,
    *,
    account_id: str,
    device_id: str,
    rp_id: str,
    login_binding: str,
    idempotency_key: str | None = None,
    source_ip_hash: str | None = None,
) -> AuthTransaction:
    """Create a fresh PENDING transaction after an RP has verified a password."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", login_binding):
        raise ValueError("login_binding must be unpadded base64url text")
    if idempotency_key is not None and not re.fullmatch(
        r"[A-Za-z0-9._:-]{1,128}", idempotency_key
    ):
        raise ValueError("idempotency_key has invalid characters or length")

    account = db.scalar(
        select(AuthAccount)
        .where(AuthAccount.id == account_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    rp = db.scalar(
        select(RelyingParty)
        .where(RelyingParty.id == rp_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    device = db.scalar(
        select(RegisteredDevice)
        .where(RegisteredDevice.id == device_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if (
        device is None
        or account is None
        or rp is None
        or device.account_id != account.id
        or account.rp_id != rp.id
    ):
        raise TransactionNotFound("Account or device is not registered for this RP")
    if device.status != "ACTIVE":
        raise DeviceRevoked(device_id)

    if idempotency_key is not None:
        existing = db.scalar(
            select(AuthTransaction)
            .where(
                AuthTransaction.rp_id == rp_id,
                AuthTransaction.idempotency_key == idempotency_key,
            )
            .with_for_update()
        )
        if existing is not None:
            if (
                existing.account_id != account_id
                or existing.device_id != device_id
                or existing.login_binding != login_binding
            ):
                raise IdempotencyKeyConflict(idempotency_key)
            return existing

    now = utcnow()
    _enforce_auth_request_limits(
        db,
        rp_id=rp_id,
        account_id=account_id,
        source_ip_hash=source_ip_hash,
        now=now,
    )
    tx = AuthTransaction(
        account_id=account_id,
        device_id=device_id,
        rp_id=rp_id,
        challenge_nonce=challenge_service.generate_nonce(),
        login_binding=login_binding,
        idempotency_key=idempotency_key,
        status="PENDING",
        attempt_count=0,
        expires_at=now + timedelta(seconds=AUTH_TX_TTL_SECONDS),
        created_at=now,
    )
    db.add(tx)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        if idempotency_key is not None:
            existing = db.scalar(
                select(AuthTransaction).where(
                    AuthTransaction.rp_id == rp_id,
                    AuthTransaction.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if (
                    existing.account_id == account_id
                    and existing.device_id == device_id
                    and existing.login_binding == login_binding
                ):
                    return existing
                raise IdempotencyKeyConflict(idempotency_key) from exc
        raise
    audit_writer.write(
        db,
        EVT_AUTH_REQUEST_CREATED,
        transaction_id=tx.id,
        actor=rp_id,
        metadata={"account_id": account_id, "device_id": device_id},
    )
    db.commit()
    return tx


def get_transaction(db: Session, tx_id: str) -> AuthTransaction:
    """Load an authentication transaction and persist expiry if necessary."""
    tx = db.get(AuthTransaction, tx_id)
    if tx is None:
        raise TransactionNotFound(tx_id)
    return _expire_if_needed(db, tx)


def mark_fetched(db: Session, tx: AuthTransaction) -> None:
    """Record the first device fetch without changing authentication state."""
    if tx.fetched_at is None:
        tx.fetched_at = utcnow()
        audit_writer.write(
            db, EVT_REQUEST_FETCHED, transaction_id=tx.id, actor=tx.device_id
        )
        db.commit()


def report_failure(
    db: Session,
    tx: AuthTransaction,
    *,
    event_id: str,
    device_id: str,
) -> AuthTransaction:
    """Atomically count an idempotent local pattern mismatch."""
    device, tx = _lock_device_then_transaction(
        db, device_id=device_id, transaction_id=tx.id
    )
    if device.status != "ACTIVE":
        raise DeviceRevoked(device_id)
    tx = _expire_if_needed(db, tx, actor=device_id)
    if tx.status == "EXPIRED":
        raise TransactionExpired(tx.id)

    existing = db.scalar(
        select(AttemptEvent).where(
            AttemptEvent.device_id == device_id,
            AttemptEvent.event_id == event_id,
        )
    )
    if existing is not None:
        raise DuplicateAttemptEvent(event_id)
    if tx.status in TERMINAL_STATES:
        raise TransactionTerminal(tx.status)

    now = utcnow()
    db.add(AttemptEvent(
        transaction_id=tx.id,
        event_id=event_id,
        device_id=device_id,
        created_at=now,
    ))
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        existing = db.scalar(
            select(AttemptEvent).where(
                AttemptEvent.device_id == device_id,
                AttemptEvent.event_id == event_id,
            )
        )
        if existing is not None:
            raise DuplicateAttemptEvent(event_id) from exc
        raise

    next_count = AuthTransaction.attempt_count + 1
    locked = next_count >= MAX_FAILURE_ATTEMPTS
    changed = db.execute(
        update(AuthTransaction)
        .where(
            AuthTransaction.id == tx.id,
            AuthTransaction.status == "PENDING",
            AuthTransaction.attempt_count < MAX_FAILURE_ATTEMPTS,
            AuthTransaction.expires_at > now,
        )
        .values(
            attempt_count=next_count,
            status=case((locked, "LOCKED"), else_="PENDING"),
            completed_at=case((locked, now), else_=None),
        )
        .execution_options(synchronize_session=False)
    )
    if changed.rowcount != 1:
        _raise_current_state(db, tx.id)

    db.refresh(tx)
    audit_writer.write(
        db,
        EVT_FAILED_PATTERN_ATTEMPT,
        transaction_id=tx.id,
        actor=device_id,
        metadata={"attempt_count": tx.attempt_count},
    )
    if tx.status == "LOCKED":
        audit_writer.write(
            db, EVT_TRANSACTION_LOCKED, transaction_id=tx.id, actor=device_id
        )
    db.commit()
    return tx


def process_decision(
    db: Session,
    tx: AuthTransaction,
    *,
    decision: str,
    signature_b64url: str,
    device: RegisteredDevice,
) -> AuthTransaction:
    """Verify a signed decision and perform one atomic terminal transition."""
    if decision not in {"APPROVE", "DENY"}:
        raise InvalidDecision(decision)

    device, tx = _lock_device_then_transaction(
        db, device_id=device.id, transaction_id=tx.id
    )
    if device.status != "ACTIVE":
        raise DeviceRevoked(device.id)
    tx = _expire_if_needed(db, tx, actor=device.id)
    if tx.status == "EXPIRED":
        raise TransactionExpired(tx.id)
    if tx.status in TERMINAL_STATES:
        raise TransactionTerminal(tx.status)
    if tx.attempt_count >= MAX_FAILURE_ATTEMPTS:
        raise TransactionLocked(tx.id)

    expires_at_unix = calendar.timegm(tx.expires_at.timetuple())
    valid = signature_service.verify_decision(
        public_key_spki_b64url=device.public_key_spki,
        signature_b64url=signature_b64url,
        transaction_id=tx.id,
        challenge_nonce=tx.challenge_nonce,
        account_id=tx.account_id,
        device_id=device.id,
        rp_id=tx.rp_id,
        login_binding=tx.login_binding,
        decision=decision,
        expires_at_unix=expires_at_unix,
    )
    now = utcnow()
    if now >= tx.expires_at:
        tx = _expire_if_needed(db, tx, actor=device.id)
        raise TransactionExpired(tx.id)
    if not valid:
        audit_writer.write(
            db, EVT_INVALID_SIGNATURE, transaction_id=tx.id, actor=device.id
        )
        db.commit()
        raise SignatureInvalid()

    next_status = "APPROVED" if decision == "APPROVE" else "DENIED"
    changed = db.execute(
        update(AuthTransaction)
        .where(
            AuthTransaction.id == tx.id,
            AuthTransaction.status == "PENDING",
            AuthTransaction.attempt_count < MAX_FAILURE_ATTEMPTS,
            AuthTransaction.expires_at > now,
        )
        .values(status=next_status, completed_at=now)
        .execution_options(synchronize_session=False)
    )
    if changed.rowcount != 1:
        _raise_current_state(db, tx.id)
    db.refresh(tx)

    if decision == "DENY":
        audit_writer.write(
            db, EVT_USER_DENIED, transaction_id=tx.id, actor=device.id
        )
        db.commit()
        return tx

    audit_writer.write(
        db, EVT_APPROVAL_VERIFIED, transaction_id=tx.id, actor=device.id
    )
    raw_code = secrets.token_urlsafe(32)
    result = AuthResult(
        transaction_id=tx.id,
        code_hash=_hash_token(raw_code),
        code_ciphertext=result_service.encrypt_result_code(tx.id, raw_code),
        login_binding=tx.login_binding,
        expires_at=min(
            tx.expires_at,
            now + timedelta(seconds=RESULT_TTL_SECONDS),
        ),
        created_at=now,
    )
    db.add(result)
    audit_writer.write(
        db, EVT_RESULT_ISSUED, transaction_id=tx.id, actor=device.id
    )
    db.commit()
    return tx
