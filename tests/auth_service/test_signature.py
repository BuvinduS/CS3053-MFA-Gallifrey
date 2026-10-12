"""Tests for the signature verification service (§10)."""
import base64
import calendar
import hashlib
import json
import secrets
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from auth_service.services.signature_service import (
    build_enrollment_message,
    build_signed_message,
    verify_decision,
    verify_enrollment_signature,
)
from auth_service.db import utcnow
from datetime import timedelta


def _gen():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.urlsafe_b64encode(pub_der).rstrip(b"=").decode()
    return priv, pub_b64


def _sign(priv, message: bytes) -> str:
    sig = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


PARAMS = dict(
    transaction_id="3f2b8c1e-4d5a-4e6f-9a7b-8c9d0e1f2a3b",
    challenge_nonce="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    account_id="11111111-2222-4333-8444-555555555555",
    device_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    rp_id="rp-1",
    login_binding="bind-abc",
    decision="APPROVE",
    expires_at_unix=9999999999,
)


def test_valid_signature_verifies():
    priv, pub = _gen()
    msg = build_signed_message(**PARAMS)
    sig = _sign(priv, msg)
    assert verify_decision(public_key_spki_b64url=pub, signature_b64url=sig, **PARAMS)


def test_wrong_key_rejected():
    priv, pub = _gen()
    priv2, _ = _gen()
    msg = build_signed_message(**PARAMS)
    sig = _sign(priv2, msg)  # signed with a DIFFERENT key
    assert not verify_decision(public_key_spki_b64url=pub, signature_b64url=sig, **PARAMS)


def test_altered_decision_rejected():
    priv, pub = _gen()
    msg = build_signed_message(**PARAMS)
    sig = _sign(priv, msg)
    altered = dict(PARAMS, decision="DENY")  # change decision after signing
    assert not verify_decision(public_key_spki_b64url=pub, signature_b64url=sig, **altered)


def test_altered_nonce_rejected():
    priv, pub = _gen()
    msg = build_signed_message(**PARAMS)
    sig = _sign(priv, msg)
    altered = dict(PARAMS, challenge_nonce="different-nonce")
    assert not verify_decision(public_key_spki_b64url=pub, signature_b64url=sig, **altered)


def test_altered_account_rejected():
    priv, pub = _gen()
    msg = build_signed_message(**PARAMS)
    sig = _sign(priv, msg)
    altered = dict(PARAMS, account_id="evil-account")
    assert not verify_decision(public_key_spki_b64url=pub, signature_b64url=sig, **altered)


def test_altered_rp_rejected():
    priv, pub = _gen()
    msg = build_signed_message(**PARAMS)
    sig = _sign(priv, msg)
    altered = dict(PARAMS, rp_id="evil-rp")
    assert not verify_decision(public_key_spki_b64url=pub, signature_b64url=sig, **altered)


def test_altered_login_binding_rejected():
    priv, pub = _gen()
    msg = build_signed_message(**PARAMS)
    sig = _sign(priv, msg)
    altered = dict(PARAMS, login_binding="x" * 43)
    assert not verify_decision(public_key_spki_b64url=pub, signature_b64url=sig, **altered)


def test_altered_transaction_id_rejected():
    priv, pub = _gen()
    msg = build_signed_message(**PARAMS)
    sig = _sign(priv, msg)
    altered = dict(PARAMS, transaction_id="tx-evil")
    assert not verify_decision(public_key_spki_b64url=pub, signature_b64url=sig, **altered)


def test_garbage_signature_rejected():
    _, pub = _gen()
    assert not verify_decision(
        public_key_spki_b64url=pub,
        signature_b64url="notavalidbase64=====GARBAGE",
        **PARAMS,
    )


def test_non_ec_key_rejected():
    """Passing an RSA key SPKI should be rejected without crashing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    priv_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = priv_rsa.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.urlsafe_b64encode(pub_der).rstrip(b"=").decode()
    priv_ec, _ = _gen()
    msg = build_signed_message(**PARAMS)
    sig = _sign(priv_ec, msg)
    assert not verify_decision(public_key_spki_b64url=pub_b64, signature_b64url=sig, **PARAMS)


def test_line_break_injection_in_field_raises():
    """A field containing a newline must raise ValueError (injection guard)."""
    with pytest.raises(ValueError):
        build_signed_message(**dict(PARAMS, transaction_id="tx\nevil"))


def test_android_protocol_vectors_match_server_encoding_and_verification():
    vector_path = (
        Path(__file__).resolve().parents[2]
        / "android/core/src/test/resources/vectors/protocol-v1.json"
    )
    vectors = json.loads(vector_path.read_text())

    for decision, message_key, signature_key in (
        ("APPROVE", "approve_message", "approve_signature"),
        ("DENY", "deny_message", "deny_signature"),
    ):
        message = build_signed_message(
            transaction_id=vectors["decision_transaction_id"],
            challenge_nonce=vectors["decision_challenge_nonce"],
            account_id=vectors["decision_account_id"],
            device_id=vectors["decision_device_id"],
            rp_id=vectors["decision_rp_id"],
            login_binding=vectors["decision_login_binding"],
            decision=decision,
            expires_at_unix=int(vectors["decision_expires_at"]),
        )
        assert message.decode("ascii") == vectors[message_key]
        assert verify_decision(
            public_key_spki_b64url=vectors["public_key_spki"],
            signature_b64url=vectors[signature_key],
            transaction_id=vectors["decision_transaction_id"],
            challenge_nonce=vectors["decision_challenge_nonce"],
            account_id=vectors["decision_account_id"],
            device_id=vectors["decision_device_id"],
            rp_id=vectors["decision_rp_id"],
            login_binding=vectors["decision_login_binding"],
            decision=decision,
            expires_at_unix=int(vectors["decision_expires_at"]),
        )

    enrollment_message = build_enrollment_message(
        enrollment_id=vectors["enroll_enrollment_id"],
        enrollment_nonce=vectors["enroll_nonce"],
        account_ref=vectors["enroll_account_ref"],
        device_id=vectors["enroll_device_id"],
        public_key_fingerprint=vectors["public_key_fingerprint"],
    )
    assert enrollment_message.decode("ascii") == vectors["enroll_message"]
    assert verify_enrollment_signature(
        public_key_spki_b64url=vectors["public_key_spki"],
        signature_b64url=vectors["enroll_signature"],
        enrollment_id=vectors["enroll_enrollment_id"],
        enrollment_nonce=vectors["enroll_nonce"],
        account_ref=vectors["enroll_account_ref"],
        device_id=vectors["enroll_device_id"],
        public_key_fingerprint=vectors["public_key_fingerprint"],
    )
