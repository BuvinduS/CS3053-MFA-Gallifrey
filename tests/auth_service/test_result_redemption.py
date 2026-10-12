"""Tests for the result redemption flow (§11, §13)."""
import hashlib
import secrets
from datetime import timedelta

import pytest
from sqlalchemy import select

from auth_service.db import utcnow
from auth_service.models.auth_result import AuthResult
from auth_service.services.result_service import (
    ResultAlreadyRedeemed,
    ResultBindingMismatch,
    ResultExpired,
    ResultNotAvailable,
    get_result_code,
    redeem_result,
)
from auth_service.services.transaction_service import create_transaction
from tests.auth_service.conftest import sign_decision
import calendar


def _approve_tx(db, tx, dev_obj, private_key):
    from auth_service.services.transaction_service import process_decision
    expires_unix = calendar.timegm(tx.expires_at.timetuple())
    sig = sign_decision(
        private_key,
        transaction_id=tx.id,
        challenge_nonce=tx.challenge_nonce,
        account_id=tx.account_id,
        device_id=dev_obj.id,
        rp_id=tx.rp_id,
        login_binding=tx.login_binding,
        decision="APPROVE",
        expires_at_unix=expires_unix,
    )
    return process_decision(db, tx, decision="APPROVE", signature_b64url=sig, device=dev_obj)


def test_redeem_once_succeeds(db, account, device, rp):
    dev_obj, private_key = device
    tx = create_transaction(
        db,
        account_id=account.id,
        device_id=dev_obj.id,
        rp_id=rp.id,
        login_binding=secrets.token_urlsafe(16),
    )
    tx = _approve_tx(db, tx, dev_obj, private_key)
    result = db.scalar(select(AuthResult).where(AuthResult.transaction_id == tx.id))
    raw_code = get_result_code(db, tx.id)
    assert raw_code
    assert result.code_hash == hashlib.sha256(raw_code.encode()).hexdigest()
    assert raw_code not in result.code_ciphertext

    redeemed_tx = redeem_result(
        db,
        result_code=raw_code,
        login_binding=tx.login_binding,
        rp_id=rp.id,
    )
    assert redeemed_tx.id == tx.id
    assert redeemed_tx.status == "APPROVED"
    db.refresh(result)
    assert result.code_ciphertext == ""


def test_redeem_twice_rejected(db, account, device, rp):
    dev_obj, private_key = device
    tx = create_transaction(
        db,
        account_id=account.id,
        device_id=dev_obj.id,
        rp_id=rp.id,
        login_binding=secrets.token_urlsafe(16),
    )
    tx = _approve_tx(db, tx, dev_obj, private_key)
    raw_code = get_result_code(db, tx.id)

    redeem_result(db, result_code=raw_code, login_binding=tx.login_binding, rp_id=rp.id)
    with pytest.raises(ResultAlreadyRedeemed):
        redeem_result(db, result_code=raw_code, login_binding=tx.login_binding, rp_id=rp.id)


def test_wrong_login_binding_rejected(db, account, device, rp):
    dev_obj, private_key = device
    tx = create_transaction(
        db,
        account_id=account.id,
        device_id=dev_obj.id,
        rp_id=rp.id,
        login_binding=secrets.token_urlsafe(16),
    )
    tx = _approve_tx(db, tx, dev_obj, private_key)
    raw_code = get_result_code(db, tx.id)

    with pytest.raises(ResultBindingMismatch):
        redeem_result(
            db,
            result_code=raw_code,
            login_binding="wrong-binding",
            rp_id=rp.id,
        )


def test_unknown_code_rejected(db, rp):
    with pytest.raises(ResultNotAvailable):
        redeem_result(
            db,
            result_code="nonexistent-code",
            login_binding="anything",
            rp_id=rp.id,
        )


def test_expired_result_rejected(db, account, device, rp):
    dev_obj, private_key = device
    tx = create_transaction(
        db,
        account_id=account.id,
        device_id=dev_obj.id,
        rp_id=rp.id,
        login_binding=secrets.token_urlsafe(16),
    )
    tx = _approve_tx(db, tx, dev_obj, private_key)
    result = db.scalar(select(AuthResult).where(AuthResult.transaction_id == tx.id))
    raw_code = get_result_code(db, tx.id)

    # Wind back expiry.
    result.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()

    with pytest.raises(ResultExpired):
        redeem_result(db, result_code=raw_code, login_binding=tx.login_binding, rp_id=rp.id)


def test_wrong_rp_rejected(db, account, device, rp):
    dev_obj, private_key = device
    tx = create_transaction(
        db,
        account_id=account.id,
        device_id=dev_obj.id,
        rp_id=rp.id,
        login_binding=secrets.token_urlsafe(16),
    )
    tx = _approve_tx(db, tx, dev_obj, private_key)
    raw_code = get_result_code(db, tx.id)

    with pytest.raises(ResultBindingMismatch):
        redeem_result(
            db,
            result_code=raw_code,
            login_binding=tx.login_binding,
            rp_id="wrong-rp-id",
        )
