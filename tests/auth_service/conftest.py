"""Shared fixtures for the authentication service test suite."""
import base64
import hashlib
import secrets
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth_service.db import Base, get_db, utcnow
from auth_service.dependencies import get_device, get_rp
from auth_service.main import app
from auth_service.models.auth_account import AuthAccount
from auth_service.models.registered_device import RegisteredDevice
from auth_service.models.relying_party import RelyingParty
from auth_service.services.challenge_service import generate_nonce
from auth_service.services.signature_service import build_signed_message

import calendar


# ---------------------------------------------------------------------------
# Crypto helpers (test only)
# ---------------------------------------------------------------------------

def gen_key_pair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Return (private_key, public_key_spki_base64url)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.urlsafe_b64encode(pub_der).rstrip(b"=").decode()
    return private_key, pub_b64


def sign_decision(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    transaction_id: str,
    challenge_nonce: str,
    account_id: str,
    device_id: str,
    rp_id: str,
    login_binding: str,
    decision: str,
    expires_at_unix: int,
) -> str:
    """Sign the canonical decision message; return base64url DER signature."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
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
    sig_der = private_key.sign(message, _ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(sig_der).rstrip(b"=").decode()


def _sha256(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session_factory(db_engine):
    return sessionmaker(bind=db_engine, autoflush=False)


@pytest.fixture
def db(db_session_factory):
    session = db_session_factory()
    yield session
    session.close()


# ---------------------------------------------------------------------------
# Seeded fixtures
# ---------------------------------------------------------------------------

RP_SECRET = "test-rp-secret-abc"
DEVICE_TOKEN = "test-device-token-xyz"


@pytest.fixture
def rp(db) -> RelyingParty:
    rp = RelyingParty(
        name="Test RP",
        client_secret_hash=_sha256(RP_SECRET),
        status="ACTIVE",
        created_at=utcnow(),
    )
    db.add(rp)
    db.commit()
    db.refresh(rp)
    return rp


@pytest.fixture
def account(db, rp) -> AuthAccount:
    acc = AuthAccount(
        rp_subject="user-001",
        rp_id=rp.id,
        created_at=utcnow(),
    )
    db.add(acc)
    db.commit()
    db.refresh(acc)
    return acc


@pytest.fixture
def key_pair():
    return gen_key_pair()


@pytest.fixture
def device(db, account, key_pair) -> tuple[RegisteredDevice, ec.EllipticCurvePrivateKey]:
    private_key, pub_spki = key_pair
    d = RegisteredDevice(
        account_id=account.id,
        public_key_spki=pub_spki,
        key_fingerprint=_sha256(pub_spki),
        device_token_hash=_sha256(DEVICE_TOKEN),
        status="ACTIVE",
        registered_at=utcnow(),
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    return d, private_key


# ---------------------------------------------------------------------------
# HTTP client fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def make_client(db_session_factory, rp, account, device):
    """HTTP client with the test DB and known credentials pre-seeded."""
    dev, private_key = device

    def override_db():
        s = db_session_factory()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app, base_url="https://testserver", raise_server_exceptions=True)
    yield client, rp, account, dev, private_key
    app.dependency_overrides.clear()


@pytest.fixture
def rp_headers():
    return {"Authorization": f"Bearer {RP_SECRET}"}


@pytest.fixture
def device_headers():
    return {"Authorization": f"Bearer {DEVICE_TOKEN}"}
