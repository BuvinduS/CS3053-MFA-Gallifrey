"""RP-facing result and management routes (§13):

  GET  /v1/rp/requests/{id}         – RP: status check
  POST /v1/rp/requests/{id}/result  – RP: get/issue result code
  POST /v1/rp/results/redeem        – RP: one-time redemption
  POST /v1/rp/requests/{id}/cancel  – RP: cancel a pending request
  POST /v1/devices/{id}/revoke      – Revoke a device
  POST /v1/recovery/start           – Recovery flow start
"""
import secrets as _secrets

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth_service.db import get_db, utcnow
from auth_service.dependencies import get_rp
from auth_service.models.audit_event import (
    EVT_DEVICE_REVOKED,
    EVT_RECOVERY_STARTED,
    EVT_TRANSACTION_CANCELLED,
    EVT_TRANSACTION_EXPIRED,
)
from auth_service.models.auth_transaction import AuthTransaction
from auth_service.models.registered_device import RegisteredDevice
from auth_service.models.relying_party import RelyingParty
from auth_service.services import audit_writer, result_service
from auth_service.services.result_service import (
    ResultAlreadyRedeemed,
    ResultBindingMismatch,
    ResultExpired,
    ResultNotAvailable,
)
from auth_service.services.transaction_service import TransactionNotFound, get_transaction

router = APIRouter(tags=["rp"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class TxStatusResponse(BaseModel):
    transaction_id: str
    status: str
    account_id: str


class ResultResponse(BaseModel):
    result_code: str | None   # only non-None when APPROVED + unredeemed


class RedeemRequest(BaseModel):
    result_code: str = Field(min_length=1, max_length=128)
    login_binding: str = Field(min_length=1, max_length=64)


class RedeemResponse(BaseModel):
    account_id: str
    transaction_id: str
    login_binding: str
    authenticated_at: str


class RevokeResponse(BaseModel):
    device_id: str
    status: str


class RecoveryStartRequest(BaseModel):
    rp_subject: str = Field(min_length=1, max_length=255)


class RecoveryStartResponse(BaseModel):
    enrollment_token: str
    expires_in_seconds: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_rp_owns_tx(tx: AuthTransaction, rp: RelyingParty) -> None:
    if tx.rp_id != rp.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Not your transaction")


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@router.get("/v1/rp/requests/{tx_id}", response_model=TxStatusResponse)
def rp_get_status(
    tx_id: str,
    rp: RelyingParty = Depends(get_rp),
    db: Session = Depends(get_db),
):
    """RP: poll the authoritative status of its MFA request."""
    try:
        tx = get_transaction(db, tx_id)
    except TransactionNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    _require_rp_owns_tx(tx, rp)
    return TxStatusResponse(
        transaction_id=tx.id,
        status=tx.status,
        account_id=tx.account.rp_subject,
    )


# ---------------------------------------------------------------------------
# Result retrieval
# ---------------------------------------------------------------------------

@router.post("/v1/rp/requests/{tx_id}/result", response_model=ResultResponse)
def rp_get_result(
    tx_id: str,
    rp: RelyingParty = Depends(get_rp),
    db: Session = Depends(get_db),
):
    """RP: retrieve the one-time result code after APPROVED.

    The raw code is never stored; only its hash is in the database.
    We cannot re-issue the raw code after commit, so the RP must redeem promptly.
    """
    try:
        tx = get_transaction(db, tx_id)
    except TransactionNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    _require_rp_owns_tx(tx, rp)

    if tx.status != "APPROVED":
        return ResultResponse(result_code=None)
    return ResultResponse(
        result_code=result_service.get_result_code(db, tx_id)
    )


# ---------------------------------------------------------------------------
# Redemption
# ---------------------------------------------------------------------------

@router.post("/v1/rp/results/redeem", response_model=RedeemResponse)
def rp_redeem(
    body: RedeemRequest,
    rp: RelyingParty = Depends(get_rp),
    db: Session = Depends(get_db),
):
    """RP: redeem the one-time result code.  Fails on replay."""
    try:
        tx = result_service.redeem_result(
            db,
            result_code=body.result_code,
            login_binding=body.login_binding,
            rp_id=rp.id,
        )
    except ResultNotAvailable:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Result not found")
    except ResultAlreadyRedeemed:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Already redeemed")
    except ResultExpired:
        raise HTTPException(status.HTTP_410_GONE, detail="Result expired")
    except ResultBindingMismatch:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Binding mismatch")

    return RedeemResponse(
        account_id=tx.account.rp_subject,
        transaction_id=tx.id,
        login_binding=tx.login_binding,
        authenticated_at=tx.completed_at.isoformat() + "Z",
    )


# ---------------------------------------------------------------------------
# Cancel
# ---------------------------------------------------------------------------

@router.post("/v1/rp/requests/{tx_id}/cancel", status_code=status.HTTP_200_OK)
def rp_cancel(
    tx_id: str,
    rp: RelyingParty = Depends(get_rp),
    db: Session = Depends(get_db),
):
    """RP: cancel a pending request (e.g. browser tab closed)."""
    try:
        tx = get_transaction(db, tx_id)
    except TransactionNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    _require_rp_owns_tx(tx, rp)

    device = db.scalar(
        select(RegisteredDevice)
        .where(RegisteredDevice.id == tx.device_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    tx = db.scalar(
        select(AuthTransaction)
        .where(AuthTransaction.id == tx.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if device is None or tx is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Transaction not found")

    now = utcnow()
    if tx.status == "PENDING":
        if now >= tx.expires_at:
            tx.status = "EXPIRED"
            audit_writer.write(
                db, EVT_TRANSACTION_EXPIRED, transaction_id=tx.id, actor="system"
            )
        else:
            tx.status = "CANCELLED"
            audit_writer.write(
                db, EVT_TRANSACTION_CANCELLED, transaction_id=tx.id, actor=rp.id
            )
        tx.completed_at = now
    elif tx.status == "APPROVED":
        result_service.invalidate_unredeemed_result(
            db, transaction_id=tx.id, actor=rp.id
        )

    db.commit()
    return {"status": tx.status}


# ---------------------------------------------------------------------------
# Device revocation
# ---------------------------------------------------------------------------

@router.post("/v1/devices/{device_id}/revoke", response_model=RevokeResponse)
def revoke_device(
    device_id: str,
    rp: RelyingParty = Depends(get_rp),
    db: Session = Depends(get_db),
):
    """Revoke a device; cancel its pending requests."""
    device = db.scalar(
        select(RegisteredDevice)
        .where(RegisteredDevice.id == device_id)
        .with_for_update()
    )
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found")

    # Confirm the device belongs to this RP's account universe.
    from auth_service.models.auth_account import AuthAccount
    account = db.get(AuthAccount, device.account_id)
    if account is None or account.rp_id != rp.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Not your device")

    if device.status != "REVOKED":
        device.status = "REVOKED"
        device.revoked_at = utcnow()

    # Cancel any pending transactions for this device.
    device_txs = db.scalars(
        select(AuthTransaction)
        .where(AuthTransaction.device_id == device_id)
        .order_by(AuthTransaction.id)
        .with_for_update()
    ).all()
    now = utcnow()
    for tx in device_txs:
        if tx.status == "PENDING":
            tx.status = "CANCELLED"
            tx.completed_at = now
            audit_writer.write(
                db, EVT_TRANSACTION_CANCELLED, transaction_id=tx.id, actor=rp.id
            )
        result_service.invalidate_unredeemed_result(
            db, transaction_id=tx.id, actor=rp.id
        )

    audit_writer.write(
        db, EVT_DEVICE_REVOKED, actor=rp.id, metadata={"device_id": device_id}
    )
    db.commit()
    return RevokeResponse(device_id=device_id, status="REVOKED")


# ---------------------------------------------------------------------------
# Recovery start
# ---------------------------------------------------------------------------

@router.post("/v1/recovery/start", response_model=RecoveryStartResponse)
def recovery_start(
    body: RecoveryStartRequest,
    rp: RelyingParty = Depends(get_rp),
    db: Session = Depends(get_db),
):
    """RP backend: initiate device replacement after password + recovery code.

    The RP has already verified the password and the recovery code before
    calling this endpoint.  We revoke the old device and issue a new
    enrollment token.
    """
    from sqlalchemy import select
    from auth_service.models.auth_account import AuthAccount
    from auth_service.services.enrollment_service import create_enrollment_token
    from auth_service.config import ENROLLMENT_TTL_SECONDS

    account = db.scalar(
        select(AuthAccount).where(
            AuthAccount.rp_id == rp.id,
            AuthAccount.rp_subject == body.rp_subject,
        )
    )
    if account is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Account not found")

    # Revoke active device.
    old_device = db.scalar(
        select(RegisteredDevice).where(
            RegisteredDevice.account_id == account.id,
            RegisteredDevice.status == "ACTIVE",
        ).with_for_update()
    )
    if old_device is not None:
        old_device.status = "REVOKED"
        old_device.revoked_at = utcnow()
        audit_writer.write(
            db,
            EVT_DEVICE_REVOKED,
            actor=rp.id,
            metadata={"device_id": old_device.id},
        )
        # Cancel pending transactions.
        device_txs = db.scalars(
            select(AuthTransaction)
            .where(AuthTransaction.device_id == old_device.id)
            .order_by(AuthTransaction.id)
            .with_for_update()
        ).all()
        now = utcnow()
        for tx in device_txs:
            if tx.status == "PENDING":
                tx.status = "CANCELLED"
                tx.completed_at = now
                audit_writer.write(
                    db,
                    EVT_TRANSACTION_CANCELLED,
                    transaction_id=tx.id,
                    actor=rp.id,
                )
            result_service.invalidate_unredeemed_result(
                db, transaction_id=tx.id, actor=rp.id
            )

    audit_writer.write(
        db, EVT_RECOVERY_STARTED, actor=rp.id, metadata={"account_id": account.id}
    )

    raw_token = create_enrollment_token(db, rp_id=rp.id, account_id=account.id)
    return RecoveryStartResponse(
        enrollment_token=raw_token,
        expires_in_seconds=ENROLLMENT_TTL_SECONDS,
    )
