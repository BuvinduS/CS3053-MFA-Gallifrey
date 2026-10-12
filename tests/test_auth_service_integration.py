import base64
import calendar
import hashlib
from datetime import datetime

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.services.http_auth_service import HttpAuthServiceClient
from auth_service.db import Base as AuthBase, get_db as get_auth_db, utcnow
from auth_service.dependencies import get_rp
from auth_service.main import app as auth_app
from auth_service.models.auth_account import AuthAccount
from auth_service.models.registered_device import RegisteredDevice
from auth_service.models.relying_party import RelyingParty
from tests.auth_service.conftest import sign_decision


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def test_website_login_completes_through_real_auth_service_api(
    make_client, login
):
    auth_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    AuthBase.metadata.create_all(auth_engine)
    auth_session_factory = sessionmaker(bind=auth_engine, autoflush=False)
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key = base64.urlsafe_b64encode(public_der).rstrip(b"=").decode()
    rp_secret = "integration-rp-secret"
    device_token = "integration-device-token"

    with auth_session_factory() as db:
        rp = RelyingParty(
            name="Integration RP",
            client_secret_hash=_hash(rp_secret),
            status="ACTIVE",
            created_at=utcnow(),
        )
        db.add(rp)
        db.flush()
        account = AuthAccount(
            rp_subject="1",
            rp_id=rp.id,
            created_at=utcnow(),
        )
        db.add(account)
        db.flush()
        db.add(RegisteredDevice(
            account_id=account.id,
            public_key_spki=public_key,
            key_fingerprint=_hash(public_key),
            device_token_hash=_hash(device_token),
            status="ACTIVE",
            registered_at=utcnow(),
        ))
        db.commit()

    def override_auth_db():
        db = auth_session_factory()
        try:
            yield db
        finally:
            db.close()

    auth_app.dependency_overrides[get_auth_db] = override_auth_db
    auth_server = TestClient(
        auth_app,
        base_url="https://auth-service.test",
        raise_server_exceptions=True,
    )

    def forward_to_auth_service(request: httpx.Request) -> httpx.Response:
        response = auth_server.request(
            request.method,
            request.url.path,
            content=request.content,
            headers=dict(request.headers),
        )
        return httpx.Response(
            response.status_code,
            headers=dict(response.headers),
            content=response.content,
            request=request,
        )

    auth_client = HttpAuthServiceClient(
        "https://auth-service.test",
        rp_secret,
        transport=httpx.MockTransport(forward_to_auth_service),
    )
    try:
        website = make_client(auth_client)
        assert login(website).status_code == 303
        assert website.get("/auth/status").json() == {"status": "PENDING"}

        device_headers = {"Authorization": f"Bearer {device_token}"}
        device_requests = auth_server.get(
            "/v1/device/requests", headers=device_headers
        )
        assert device_requests.status_code == 200
        detail = device_requests.json()[0]
        expires_unix = calendar.timegm(
            datetime.fromisoformat(detail["expires_at"].rstrip("Z")).timetuple()
        )
        signature = sign_decision(
            private_key,
            transaction_id=detail["transaction_id"],
            challenge_nonce=detail["challenge_nonce"],
            account_id=detail["account_id"],
            device_id=detail["device_id"],
            rp_id=detail["rp_id"],
            login_binding=detail["login_binding"],
            decision="APPROVE",
            expires_at_unix=expires_unix,
        )
        approved = auth_server.post(
            f"/v1/device/requests/{detail['transaction_id']}/decision",
            json={"decision": "APPROVE", "signature": signature},
            headers=device_headers,
        )
        assert approved.status_code == 200
        assert website.get("/auth/status").json() == {"status": "APPROVED"}

        completed = website.post("/auth/complete")
        assert completed.status_code == 200
        assert completed.json()["status"] == "AUTHENTICATED"
        assert website.get("/dashboard").status_code == 200
    finally:
        auth_client.close()
        auth_app.dependency_overrides.clear()
        auth_engine.dispose()
