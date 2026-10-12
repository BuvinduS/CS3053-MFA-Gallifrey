"""BT-01 to BT-12 – Backend test plan from mypart.md §12.

Maps each test ID to the exact scenario and expected result.
"""
import calendar
import hashlib
import secrets
from datetime import timedelta

import pytest
from sqlalchemy import select

from auth_service.db import utcnow
from auth_service.models.auth_result import AuthResult
from auth_service.models.auth_transaction import AuthTransaction
from auth_service.models.attempt_event import AttemptEvent
from auth_service.models.audit_event import AuditEvent
from auth_service.services.transaction_service import (
    create_transaction,
    get_transaction,
    process_decision,
    report_failure,
    TransactionLocked,
    TransactionTerminal,
)
from tests.auth_service.conftest import sign_decision, DEVICE_TOKEN, RP_SECRET

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tx(db, account, device_obj, rp):
    return create_transaction(
        db,
        account_id=account.id,
        device_id=device_obj.id,
        rp_id=rp.id,
        login_binding=secrets.token_urlsafe(16),
    )


def _approve(db, tx, dev_obj, private_key):
    """Sign and submit an APPROVE decision; return the (updated tx, raw_code)."""
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
    tx = process_decision(db, tx, decision="APPROVE", signature_b64url=sig, device=dev_obj)
    # Reload from DB.
    db.refresh(tx)
    result = db.scalar(select(AuthResult).where(AuthResult.transaction_id == tx.id))
    from auth_service.services.result_service import get_result_code
    raw_code = get_result_code(db, tx.id)
    return tx, raw_code


# ---------------------------------------------------------------------------
# BT-01 – create request: PENDING, unique nonce, future expiry
# ---------------------------------------------------------------------------

def test_BT01_create_transaction(db, account, device, rp):
    dev_obj, _ = device
    tx = _make_tx(db, account, dev_obj, rp)

    assert tx.status == "PENDING"
    assert tx.challenge_nonce  # non-empty
    assert len(tx.challenge_nonce) > 20
    assert tx.expires_at > tx.created_at
    assert tx.attempt_count == 0


# ---------------------------------------------------------------------------
# BT-02 – valid signed approval before expiry → APPROVED
# ---------------------------------------------------------------------------

def test_BT02_valid_approval(db, account, device, rp):
    dev_obj, private_key = device
    tx = _make_tx(db, account, dev_obj, rp)
    tx, _ = _approve(db, tx, dev_obj, private_key)

    assert tx.status == "APPROVED"


# ---------------------------------------------------------------------------
# BT-03 – replay the same approval → rejected (already terminal)
# ---------------------------------------------------------------------------

def test_BT03_replay_rejected(db, account, device, rp):
    from auth_service.services.transaction_service import SignatureInvalid
    dev_obj, private_key = device
    tx = _make_tx(db, account, dev_obj, rp)
    tx, _ = _approve(db, tx, dev_obj, private_key)

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
    with pytest.raises(TransactionTerminal):
        process_decision(db, tx, decision="APPROVE", signature_b64url=sig, device=dev_obj)


# ---------------------------------------------------------------------------
# BT-04 – altered payload → signature fails, state stays non-APPROVED
# ---------------------------------------------------------------------------

def test_BT04_tampered_payload_rejected(db, account, device, rp):
    from auth_service.services.transaction_service import SignatureInvalid
    dev_obj, private_key = device
    tx = _make_tx(db, account, dev_obj, rp)

    expires_unix = calendar.timegm(tx.expires_at.timetuple())
    # Sign with wrong decision value – message mismatch.
    sig = sign_decision(
        private_key,
        transaction_id=tx.id,
        challenge_nonce=tx.challenge_nonce,
        account_id=tx.account_id,
        device_id=dev_obj.id,
        rp_id=tx.rp_id,
        login_binding=tx.login_binding,
        decision="DENY",          # sign DENY but submit APPROVE
        expires_at_unix=expires_unix,
    )
    with pytest.raises(SignatureInvalid):
        process_decision(db, tx, decision="APPROVE", signature_b64url=sig, device=dev_obj)

    db.refresh(tx)
    assert tx.status not in ("APPROVED",)


# ---------------------------------------------------------------------------
# BT-05 – submit approval after expiry → EXPIRED
# ---------------------------------------------------------------------------

def test_BT05_expired_transaction(db, account, device, rp, monkeypatch):
    from auth_service.services.transaction_service import TransactionExpired
    dev_obj, private_key = device
    tx = _make_tx(db, account, dev_obj, rp)

    # Advance the service clock without violating the expiry-after-creation constraint.
    import auth_service.services.transaction_service as transaction_service
    monkeypatch.setattr(
        transaction_service,
        "utcnow",
        lambda: tx.expires_at + timedelta(seconds=1),
    )

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
    with pytest.raises(TransactionExpired):
        process_decision(db, tx, decision="APPROVE", signature_b64url=sig, device=dev_obj)

    db.refresh(tx)
    assert tx.status == "EXPIRED"


# ---------------------------------------------------------------------------
# BT-06 – approval from revoked device → rejected
# ---------------------------------------------------------------------------

def test_BT06_revoked_device_rejected(db, account, device, rp):
    from auth_service.services.transaction_service import DeviceRevoked
    dev_obj, private_key = device
    tx = _make_tx(db, account, dev_obj, rp)

    dev_obj.status = "REVOKED"
    db.commit()

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
    with pytest.raises(DeviceRevoked):
        process_decision(db, tx, decision="APPROVE", signature_b64url=sig, device=dev_obj)


# ---------------------------------------------------------------------------
# BT-07 – three failed attempts → LOCKED
# ---------------------------------------------------------------------------

def test_BT07_three_failures_lock(db, account, device, rp):
    dev_obj, _ = device
    tx = _make_tx(db, account, dev_obj, rp)

    for i in range(3):
        tx = report_failure(db, tx, event_id=f"evt-{i}", device_id=dev_obj.id)

    db.refresh(tx)
    assert tx.status == "LOCKED"
    assert tx.attempt_count == 3


# ---------------------------------------------------------------------------
# BT-08 – attempt approval after LOCKED → rejected
# ---------------------------------------------------------------------------

def test_BT08_approval_after_locked(db, account, device, rp):
    dev_obj, private_key = device
    tx = _make_tx(db, account, dev_obj, rp)
    for i in range(3):
        tx = report_failure(db, tx, event_id=f"lk-{i}", device_id=dev_obj.id)

    db.refresh(tx)
    assert tx.status == "LOCKED"

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
    with pytest.raises(TransactionTerminal):
        process_decision(db, tx, decision="APPROVE", signature_b64url=sig, device=dev_obj)


# ---------------------------------------------------------------------------
# BT-09 – two transactions have different nonces
# ---------------------------------------------------------------------------

def test_BT09_nonces_are_unique(db, account, device, rp):
    dev_obj, _ = device
    tx1 = _make_tx(db, account, dev_obj, rp)
    tx2 = _make_tx(db, account, dev_obj, rp)
    assert tx1.challenge_nonce != tx2.challenge_nonce


# ---------------------------------------------------------------------------
# BT-10 – audit log contains no raw patterns, passwords, private keys or tokens
# ---------------------------------------------------------------------------

def test_BT10_no_secrets_in_audit_log(db, account, device, rp):
    dev_obj, private_key = device
    tx = _make_tx(db, account, dev_obj, rp)
    report_failure(db, tx, event_id="evt-safe", device_id=dev_obj.id)

    events = db.scalars(select(AuditEvent)).all()
    assert events  # at least one event exists

    forbidden_substrings = [
        DEVICE_TOKEN,       # raw device API token
        RP_SECRET,          # raw RP secret
        tx.challenge_nonce, # nonce should not appear as-is in metadata values
    ]
    for evt in events:
        meta = evt.metadata_json or ""
        for bad in forbidden_substrings:
            assert bad not in meta, (
                f"Secret found in audit event {evt.event_type}: {meta!r}"
            )
        # Event type field should be a safe constant, not raw data
        assert len(evt.event_type) < 64


# ---------------------------------------------------------------------------
# BT-11 – concurrent approval: only one transition succeeds
# ---------------------------------------------------------------------------

def test_BT11_concurrent_approval(db, account, device, rp):
    """Simulate two near-simultaneous decisions: only one APPROVED allowed."""
    dev_obj, private_key = device
    tx = _make_tx(db, account, dev_obj, rp)

    expires_unix = calendar.timegm(tx.expires_at.timetuple())

    def make_sig(decision):
        return sign_decision(
            private_key,
            transaction_id=tx.id,
            challenge_nonce=tx.challenge_nonce,
            account_id=tx.account_id,
            device_id=dev_obj.id,
            rp_id=tx.rp_id,
            login_binding=tx.login_binding,
            decision=decision,
            expires_at_unix=expires_unix,
        )

    sig_approve = make_sig("APPROVE")
    tx = process_decision(db, tx, decision="APPROVE", signature_b64url=sig_approve, device=dev_obj)
    db.refresh(tx)
    assert tx.status == "APPROVED"

    # Second attempt must fail with TransactionTerminal.
    sig2 = make_sig("APPROVE")
    with pytest.raises(TransactionTerminal):
        process_decision(db, tx, decision="APPROVE", signature_b64url=sig2, device=dev_obj)

    # Only one AuthResult row for this transaction.
    results = db.scalars(
        select(AuthResult).where(AuthResult.transaction_id == tx.id)
    ).all()
    assert len(results) == 1


# ---------------------------------------------------------------------------
# BT-12 – RP polls PENDING then APPROVED: correct authoritative state
# ---------------------------------------------------------------------------

def test_BT12_rp_status_poll(db, account, device, rp):
    dev_obj, private_key = device
    tx = _make_tx(db, account, dev_obj, rp)

    # Before approval: PENDING.
    loaded = get_transaction(db, tx.id)
    assert loaded.status == "PENDING"

    # After approval: APPROVED.
    tx, _ = _approve(db, tx, dev_obj, private_key)
    loaded = get_transaction(db, tx.id)
    assert loaded.status == "APPROVED"


# ---------------------------------------------------------------------------
# Extra: idempotent failure event (D02 – retried delivery cannot double-count)
# ---------------------------------------------------------------------------

def test_failure_event_idempotency(db, account, device, rp):
    from auth_service.services.transaction_service import DuplicateAttemptEvent
    dev_obj, _ = device
    tx = _make_tx(db, account, dev_obj, rp)

    report_failure(db, tx, event_id="evt-same", device_id=dev_obj.id)
    db.refresh(tx)
    assert tx.attempt_count == 1

    with pytest.raises(DuplicateAttemptEvent):
        report_failure(db, tx, event_id="evt-same", device_id=dev_obj.id)

    db.refresh(tx)
    assert tx.attempt_count == 1  # not incremented twice
