"""Device-facing routes (§13):

  POST /v1/auth-requests                       – RP creates a request
  GET  /v1/device/requests                     – Device: list pending
  GET  /v1/device/requests/{id}                – Device: fetch details
  POST /v1/device/requests/{id}/failures       – Device: report mismatch
  POST /v1/device/requests/{id}/decision       – Device: APPROVE or DENY
"""
import calendar

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth_service.db import get_db
from auth_service.dependencies import get_device, get_rp
from auth_service.models.auth_account import AuthAccount
from auth_service.models.auth_transaction import AuthTransaction
from auth_service.models.registered_device import RegisteredDevice
from auth_service.models.relying_party import RelyingParty
from auth_service.services.transaction_service import (
    DeviceRevoked,
    DuplicateAttemptEvent,
    IdempotencyKeyConflict,
    InvalidDecision,
    RequestRateLimited,
    SignatureInvalid,
    TransactionExpired,
    TransactionLocked,
    TransactionNotFound,
    TransactionTerminal,
    create_transaction,
    get_transaction,
    hash_source_ip,
    mark_fetched,
    process_decision,
    report_failure,
)

router = APIRouter(tags=["auth"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AuthRequestCreate(BaseModel):
    rp_subject: str = Field(min_length=1, max_length=255)
    login_binding: str = Field(
        min_length=1,
        max_length=64,
        pattern="^[A-Za-z0-9_-]+$",
    )


class AuthRequestCreated(BaseModel):
    transaction_id: str
    expires_at: str      # ISO-8601


class TransactionDetail(BaseModel):
    transaction_id: str
    device_id: str
    status: str
    challenge_nonce: str
    rp_id: str
    relying_party_name: str
    account_id: str
    login_binding: str
    attempt_count: int
    expires_at: str
    expires_at_epoch_seconds: int


class FailureReport(BaseModel):
    event_id: str = Field(min_length=1, max_length=36)


class FailureResponse(BaseModel):
    attempt_count: int
    status: str


class DecisionRequest(BaseModel):
    decision: str = Field(min_length=1, max_length=7)
    signature: str = Field(min_length=1, max_length=256)


class DecisionResponse(BaseModel):
    status: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_account(db: Session, rp_id: str, rp_subject: str) -> AuthAccount:
    account = db.scalar(
        select(AuthAccount).where(
            AuthAccount.rp_id == rp_id,
            AuthAccount.rp_subject == rp_subject,
        )
    )
    if account is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Account not found")
    return account


def _get_active_device(db: Session, account_id: str) -> RegisteredDevice:
    device = db.scalar(
        select(RegisteredDevice).where(
            RegisteredDevice.account_id == account_id,
            RegisteredDevice.status == "ACTIVE",
        )
    )
    if device is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail="No active device for account"
        )
    return device


def _require_own_tx(tx: AuthTransaction, device: RegisteredDevice) -> None:
    """Enforce that the requesting device owns this transaction."""
    if tx.device_id != device.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Not your transaction")


# ---------------------------------------------------------------------------
# RP: create auth request
# ---------------------------------------------------------------------------

@router.post(
    "/v1/auth-requests",
    status_code=status.HTTP_201_CREATED,
    response_model=AuthRequestCreated,
)
def create_auth_request(
    body: AuthRequestCreate,
    request: Request,
    idempotency_key: str = Header(
        min_length=1, max_length=128, alias="Idempotency-Key"
    ),
    rp: RelyingParty = Depends(get_rp),
    db: Session = Depends(get_db),
):
    """RP backend: initiate MFA after password success."""
    account = _get_account(db, rp.id, body.rp_subject)
    device = _get_active_device(db, account.id)

    try:
        tx = create_transaction(
            db,
            account_id=account.id,
            device_id=device.id,
            rp_id=rp.id,
            login_binding=body.login_binding,
            idempotency_key=idempotency_key,
            source_ip_hash=hash_source_ip(
                request.client.host if request.client else None
            ),
        )
    except IdempotencyKeyConflict:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Idempotency-Key was already used for another request",
        )
    except RequestRateLimited as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication requests",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )
    except DeviceRevoked:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Device inactive")
    return AuthRequestCreated(
        transaction_id=tx.id,
        expires_at=tx.expires_at.isoformat() + "Z",
    )


# ---------------------------------------------------------------------------
# Device: list / fetch requests
# ---------------------------------------------------------------------------

@router.get("/v1/device/requests", response_model=list[TransactionDetail])
def list_device_requests(
    device: RegisteredDevice = Depends(get_device),
    db: Session = Depends(get_db),
):
    """Mobile: return this device's pending requests."""
    txs = db.scalars(
        select(AuthTransaction).where(
            AuthTransaction.device_id == device.id,
            AuthTransaction.status == "PENDING",
        )
    ).all()
    results = []
    for tx in txs:
        tx = get_transaction(db, tx.id)
        if tx.status == "PENDING":
            mark_fetched(db, tx)
            results.append(tx)
    return [_tx_detail(t) for t in results]


@router.get("/v1/device/requests/{tx_id}", response_model=TransactionDetail)
def get_device_request(
    tx_id: str,
    device: RegisteredDevice = Depends(get_device),
    db: Session = Depends(get_db),
):
    """Mobile: fetch a specific request."""
    try:
        tx = get_transaction(db, tx_id)
    except TransactionNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    _require_own_tx(tx, device)
    mark_fetched(db, tx)
    return _tx_detail(tx)


def _tx_detail(tx: AuthTransaction) -> TransactionDetail:
    return TransactionDetail(
        transaction_id=tx.id,
        device_id=tx.device_id,
        status=tx.status,
        challenge_nonce=tx.challenge_nonce,
        rp_id=tx.rp_id,
        relying_party_name=tx.relying_party.name,
        account_id=tx.account_id,
        login_binding=tx.login_binding,
        attempt_count=tx.attempt_count,
        expires_at=tx.expires_at.isoformat() + "Z",
        expires_at_epoch_seconds=calendar.timegm(tx.expires_at.timetuple()),
    )


# ---------------------------------------------------------------------------
# Device: report failure
# ---------------------------------------------------------------------------

@router.post(
    "/v1/device/requests/{tx_id}/failures",
    response_model=FailureResponse,
)
def report_failure_endpoint(
    tx_id: str,
    body: FailureReport,
    device: RegisteredDevice = Depends(get_device),
    db: Session = Depends(get_db),
):
    """Mobile: report one failed pattern attempt (raw pattern NOT transmitted)."""
    try:
        tx = get_transaction(db, tx_id)
    except TransactionNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    _require_own_tx(tx, device)

    try:
        tx = report_failure(
            db, tx, event_id=body.event_id, device_id=device.id
        )
    except DuplicateAttemptEvent:
        pass  # idempotent – just return current state
    except TransactionExpired:
        raise HTTPException(status.HTTP_410_GONE, detail="EXPIRED")
    except DeviceRevoked:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Device inactive")
    except TransactionLocked:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="LOCKED")
    except TransactionTerminal as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=tx.status)

    return FailureResponse(attempt_count=tx.attempt_count, status=tx.status)


# ---------------------------------------------------------------------------
# Device: submit decision
# ---------------------------------------------------------------------------

@router.post(
    "/v1/device/requests/{tx_id}/decision",
    response_model=DecisionResponse,
)
def submit_decision(
    tx_id: str,
    body: DecisionRequest,
    device: RegisteredDevice = Depends(get_device),
    db: Session = Depends(get_db),
):
    """Mobile: submit a signed APPROVE or DENY decision."""
    if body.decision not in ("APPROVE", "DENY"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="decision must be APPROVE or DENY")

    try:
        tx = get_transaction(db, tx_id)
    except TransactionNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    _require_own_tx(tx, device)

    try:
        tx = process_decision(
            db, tx,
            decision=body.decision,
            signature_b64url=body.signature,
            device=device,
        )
    except DeviceRevoked:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Device revoked")
    except TransactionExpired:
        raise HTTPException(status.HTTP_410_GONE, detail="EXPIRED")
    except TransactionTerminal as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    except TransactionLocked:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="LOCKED")
    except SignatureInvalid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Signature invalid")
    except InvalidDecision:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid decision")

    return DecisionResponse(status=tx.status)
