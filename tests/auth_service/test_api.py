"""HTTP-level API tests – verifying route behaviour, status codes and auth guards."""
import base64
import calendar
import hashlib
import secrets
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from fastapi.testclient import TestClient

from auth_service.db import utcnow
from auth_service.models.auth_transaction import AuthTransaction
from auth_service.services.signature_service import build_enrollment_message
from auth_service.services.transaction_service import create_transaction
from auth_service.main import app
from tests.auth_service.conftest import (
    DEVICE_TOKEN,
    RP_SECRET,
    gen_key_pair,
    sign_decision,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tx(client, rp_headers, account, rp):
    headers = {
        **rp_headers,
        "Idempotency-Key": secrets.token_urlsafe(18),
    }
    r = client.post(
        "/v1/auth-requests",
        json={"rp_subject": "user-001", "login_binding": secrets.token_urlsafe(16)},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()["transaction_id"]


def _sign(private_key, *, tx_id, tx_detail, decision="APPROVE"):
    return sign_decision(
        private_key,
        transaction_id=tx_id,
        challenge_nonce=tx_detail["challenge_nonce"],
        account_id=tx_detail["account_id"],
        device_id=tx_detail["device_id"] if "device_id" in tx_detail else "",
        rp_id=tx_detail["rp_id"],
        login_binding=tx_detail["login_binding"],
        decision=decision,
        expires_at_unix=int(
            __import__("datetime").datetime.fromisoformat(
                tx_detail["expires_at"].rstrip("Z")
            ).timestamp()
        ),
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health(make_client):
    client, *_ = make_client
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_remote_http_request_requires_tls():
    client = TestClient(
        app,
        base_url="http://auth.example.test",
        client=("203.0.113.10", 443),
    )
    response = client.get("/health")
    assert response.status_code == 426
    assert response.json() == {"detail": "HTTPS is required"}


# ---------------------------------------------------------------------------
# Auth required
# ---------------------------------------------------------------------------

def test_rp_endpoints_require_auth(make_client):
    client, *_ = make_client
    r = client.post(
        "/v1/auth-requests",
        json={"rp_subject": "x", "login_binding": "y"},
        headers={"Idempotency-Key": "auth-required"},
    )
    assert r.status_code == 401


def test_device_endpoints_require_auth(make_client):
    client, *_ = make_client
    r = client.get("/v1/device/requests")
    assert r.status_code == 401


def test_invalid_rp_token_rejected(make_client):
    client, *_ = make_client
    r = client.post(
        "/v1/auth-requests",
        json={"rp_subject": "x", "login_binding": "y"},
        headers={
            "Authorization": "Bearer wrong-secret",
            "Idempotency-Key": "invalid-token",
        },
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Create request
# ---------------------------------------------------------------------------

def test_create_auth_request(make_client, rp_headers):
    client, rp, account, dev, private_key = make_client
    r = client.post(
        "/v1/auth-requests",
        json={"rp_subject": "user-001", "login_binding": secrets.token_urlsafe(16)},
        headers={**rp_headers, "Idempotency-Key": "create-request"},
    )
    assert r.status_code == 201
    data = r.json()
    assert "transaction_id" in data
    assert "expires_at" in data


def test_auth_request_requires_idempotency_key(make_client, rp_headers):
    client, *_ = make_client
    response = client.post(
        "/v1/auth-requests",
        json={"rp_subject": "user-001", "login_binding": secrets.token_urlsafe(16)},
        headers=rp_headers,
    )
    assert response.status_code == 422


def test_auth_request_idempotency_returns_same_transaction(make_client, rp_headers):
    client, *_ = make_client
    body = {
        "rp_subject": "user-001",
        "login_binding": secrets.token_urlsafe(16),
    }
    headers = {**rp_headers, "Idempotency-Key": "same-login-retry"}
    first = client.post("/v1/auth-requests", json=body, headers=headers)
    second = client.post("/v1/auth-requests", json=body, headers=headers)

    assert first.status_code == second.status_code == 201
    assert first.json()["transaction_id"] == second.json()["transaction_id"]

    different_login = client.post(
        "/v1/auth-requests",
        json={**body, "login_binding": secrets.token_urlsafe(16)},
        headers=headers,
    )
    assert different_login.status_code == 409


def test_auth_request_account_rate_limit_returns_retry_after(
    make_client, rp_headers
):
    client, *_ = make_client
    for _ in range(3):
        response = client.post(
            "/v1/auth-requests",
            json={
                "rp_subject": "user-001",
                "login_binding": secrets.token_urlsafe(16),
            },
            headers={**rp_headers, "Idempotency-Key": secrets.token_urlsafe(18)},
        )
        assert response.status_code == 201

    limited = client.post(
        "/v1/auth-requests",
        json={"rp_subject": "user-001", "login_binding": secrets.token_urlsafe(16)},
        headers={**rp_headers, "Idempotency-Key": secrets.token_urlsafe(18)},
    )
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) > 0


def test_auth_request_ip_rate_limit_is_enforced(
    make_client, rp_headers, monkeypatch
):
    import auth_service.services.transaction_service as transaction_service

    monkeypatch.setattr(transaction_service, "MAX_AUTH_REQUESTS_PER_ACCOUNT", 100)
    monkeypatch.setattr(transaction_service, "MAX_AUTH_REQUESTS_PER_IP", 2)
    client, *_ = make_client

    for _ in range(2):
        response = client.post(
            "/v1/auth-requests",
            json={
                "rp_subject": "user-001",
                "login_binding": secrets.token_urlsafe(16),
            },
            headers={**rp_headers, "Idempotency-Key": secrets.token_urlsafe(18)},
        )
        assert response.status_code == 201

    limited = client.post(
        "/v1/auth-requests",
        json={"rp_subject": "user-001", "login_binding": secrets.token_urlsafe(16)},
        headers={**rp_headers, "Idempotency-Key": secrets.token_urlsafe(18)},
    )
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) > 0


# ---------------------------------------------------------------------------
# Device fetch
# ---------------------------------------------------------------------------

def test_device_can_fetch_request(make_client, rp_headers, device_headers):
    client, rp, account, dev, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)

    r = client.get(f"/v1/device/requests/{tx_id}", headers=device_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "PENDING"
    assert data["challenge_nonce"]
    assert data["expires_at_epoch_seconds"] == calendar.timegm(
        __import__("datetime").datetime.fromisoformat(
            data["expires_at"].rstrip("Z")
        ).timetuple()
    )


# ---------------------------------------------------------------------------
# Device cannot access another device's request
# ---------------------------------------------------------------------------

def test_device_cannot_access_other_tx(make_client, rp_headers):
    client, rp, account, dev, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)

    other_token = "totally-different-token"
    r = client.get(
        f"/v1/device/requests/{tx_id}",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Failure reporting
# ---------------------------------------------------------------------------

def test_failure_increments_attempt_count(make_client, rp_headers, device_headers):
    client, rp, account, dev, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)

    r = client.post(
        f"/v1/device/requests/{tx_id}/failures",
        json={"event_id": "evt-001"},
        headers=device_headers,
    )
    assert r.status_code == 200
    assert r.json()["attempt_count"] == 1


def test_three_failures_lock(make_client, rp_headers, device_headers):
    client, rp, account, dev, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)

    for i in range(3):
        client.post(
            f"/v1/device/requests/{tx_id}/failures",
            json={"event_id": f"evt-{i}"},
            headers=device_headers,
        )

    r = client.get(f"/v1/device/requests/{tx_id}", headers=device_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "LOCKED"


def test_failure_event_idempotency_via_api(make_client, rp_headers, device_headers):
    client, rp, account, dev, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)

    # First call.
    r1 = client.post(
        f"/v1/device/requests/{tx_id}/failures",
        json={"event_id": "same-id"},
        headers=device_headers,
    )
    assert r1.status_code == 200
    assert r1.json()["attempt_count"] == 1

    # Second call with identical event_id – idempotent.
    r2 = client.post(
        f"/v1/device/requests/{tx_id}/failures",
        json={"event_id": "same-id"},
        headers=device_headers,
    )
    assert r2.status_code == 200
    assert r2.json()["attempt_count"] == 1  # still 1


# ---------------------------------------------------------------------------
# Decision – approve happy path
# ---------------------------------------------------------------------------

def test_approve_happy_path(make_client, rp_headers, device_headers):
    client, rp, account, dev, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)

    detail = client.get(f"/v1/device/requests/{tx_id}", headers=device_headers).json()

    sig = sign_decision(
        private_key,
        transaction_id=tx_id,
        challenge_nonce=detail["challenge_nonce"],
        account_id=detail["account_id"],
        device_id=dev.id,
        rp_id=detail["rp_id"],
        login_binding=detail["login_binding"],
        decision="APPROVE",
        expires_at_unix=calendar.timegm(
            __import__("datetime").datetime.fromisoformat(
                detail["expires_at"].rstrip("Z")
            ).timetuple()
        ),
    )
    r = client.post(
        f"/v1/device/requests/{tx_id}/decision",
        json={"decision": "APPROVE", "signature": sig},
        headers=device_headers,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "APPROVED"


# ---------------------------------------------------------------------------
# Decision – bad signature
# ---------------------------------------------------------------------------

def test_bad_signature_rejected(make_client, rp_headers, device_headers):
    client, rp, account, dev, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)

    r = client.post(
        f"/v1/device/requests/{tx_id}/decision",
        json={"decision": "APPROVE", "signature": "notavalidsignature"},
        headers=device_headers,
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Cancel
# ---------------------------------------------------------------------------

def test_rp_can_cancel(make_client, rp_headers, device_headers):
    client, rp, account, dev, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)

    r = client.post(f"/v1/rp/requests/{tx_id}/cancel", headers=rp_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "CANCELLED"

    # Device now gets CANCELLED status.
    r2 = client.get(f"/v1/device/requests/{tx_id}", headers=device_headers)
    assert r2.status_code == 200
    assert r2.json()["status"] == "CANCELLED"


# ---------------------------------------------------------------------------
# RP status
# ---------------------------------------------------------------------------

def test_rp_status_endpoint(make_client, rp_headers, device_headers):
    client, rp, account, dev, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)

    r = client.get(f"/v1/rp/requests/{tx_id}", headers=rp_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "PENDING"
    assert r.json()["account_id"] == "user-001"


def test_approved_result_can_be_retried_then_redeemed_once(
    make_client, rp_headers, device_headers
):
    client, rp, account, dev, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)
    detail = client.get(
        f"/v1/device/requests/{tx_id}", headers=device_headers
    ).json()
    signature = sign_decision(
        private_key,
        transaction_id=tx_id,
        challenge_nonce=detail["challenge_nonce"],
        account_id=detail["account_id"],
        device_id=dev.id,
        rp_id=detail["rp_id"],
        login_binding=detail["login_binding"],
        decision="APPROVE",
        expires_at_unix=calendar.timegm(
            __import__("datetime").datetime.fromisoformat(
                detail["expires_at"].rstrip("Z")
            ).timetuple()
        ),
    )
    approved = client.post(
        f"/v1/device/requests/{tx_id}/decision",
        json={"decision": "APPROVE", "signature": signature},
        headers=device_headers,
    )
    assert approved.status_code == 200

    result_path = f"/v1/rp/requests/{tx_id}/result"
    first = client.post(result_path, headers=rp_headers)
    retry = client.post(result_path, headers=rp_headers)
    assert first.status_code == retry.status_code == 200
    result_code = first.json()["result_code"]
    assert result_code
    assert retry.json()["result_code"] == result_code
    assert first.headers["cache-control"] == "no-store"

    redemption = client.post(
        "/v1/rp/results/redeem",
        json={"result_code": result_code, "login_binding": detail["login_binding"]},
        headers=rp_headers,
    )
    assert redemption.status_code == 200
    assert redemption.json()["account_id"] == "user-001"
    replay = client.post(
        "/v1/rp/results/redeem",
        json={"result_code": result_code, "login_binding": detail["login_binding"]},
        headers=rp_headers,
    )
    assert replay.status_code == 409
    assert client.post(result_path, headers=rp_headers).json()["result_code"] is None


def test_enrollment_replaces_the_active_device_and_cancels_its_requests(
    make_client, rp_headers, device_headers
):
    client, rp, account, _, _ = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)
    enrollment = client.post(
        "/v1/enrollments",
        json={"rp_subject": "user-001"},
        headers=rp_headers,
    )
    assert enrollment.status_code == 201

    private_key, public_key = gen_key_pair()
    claim = client.post(
        "/v1/enrollments/claim",
        json={
            "enrollment_token": enrollment.json()["enrollment_token"],
            "public_key_spki": public_key,
        },
    )
    assert claim.status_code == 200
    claim_data = claim.json()
    assert claim_data["account_ref"] == account.id
    assert claim_data["public_key_fingerprint"]
    message = build_enrollment_message(
        enrollment_id=claim_data["enrollment_id"],
        enrollment_nonce=claim_data["challenge_nonce"],
        account_ref=claim_data["account_ref"],
        device_id=claim_data["device_id"],
        public_key_fingerprint=claim_data["public_key_fingerprint"],
    )
    proof = private_key.sign(
        message, ec.ECDSA(hashes.SHA256())
    )
    proof_b64 = base64.urlsafe_b64encode(proof).rstrip(b"=").decode()
    completed = client.post(
        f"/v1/enrollments/{claim_data['enrollment_id']}/complete",
        json={"signature": proof_b64},
    )
    assert completed.status_code == 200

    new_headers = {
        "Authorization": f"Bearer {completed.json()['device_api_token']}"
    }
    assert client.get("/v1/device/requests", headers=new_headers).status_code == 200
    old_device_result = client.get(
        f"/v1/device/requests/{tx_id}", headers=device_headers
    )
    assert old_device_result.status_code == 403
    status_result = client.get(
        f"/v1/rp/requests/{tx_id}", headers=rp_headers
    )
    assert status_result.json()["status"] == "CANCELLED"


def test_device_revocation_invalidates_an_unredeemed_approval_result(
    make_client, rp_headers, device_headers
):
    client, rp, account, device, private_key = make_client
    tx_id = _make_tx(client, rp_headers, account, rp)
    detail = client.get(
        f"/v1/device/requests/{tx_id}", headers=device_headers
    ).json()
    expires_unix = calendar.timegm(
        __import__("datetime").datetime.fromisoformat(
            detail["expires_at"].rstrip("Z")
        ).timetuple()
    )
    signature = sign_decision(
        private_key,
        transaction_id=tx_id,
        challenge_nonce=detail["challenge_nonce"],
        account_id=detail["account_id"],
        device_id=device.id,
        rp_id=detail["rp_id"],
        login_binding=detail["login_binding"],
        decision="APPROVE",
        expires_at_unix=expires_unix,
    )
    approved = client.post(
        f"/v1/device/requests/{tx_id}/decision",
        json={"decision": "APPROVE", "signature": signature},
        headers=device_headers,
    )
    assert approved.status_code == 200

    result_response = client.post(
        f"/v1/rp/requests/{tx_id}/result", headers=rp_headers
    )
    result_code = result_response.json()["result_code"]
    assert result_code

    revoked = client.post(
        f"/v1/devices/{device.id}/revoke", headers=rp_headers
    )
    assert revoked.status_code == 200
    assert client.post(
        f"/v1/rp/requests/{tx_id}/result", headers=rp_headers
    ).json()["result_code"] is None

    redeem = client.post(
        "/v1/rp/results/redeem",
        json={"result_code": result_code, "login_binding": detail["login_binding"]},
        headers=rp_headers,
    )
    assert redeem.status_code == 404
