import dataclasses
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.db import utcnow
from app.models import PendingLogin, WebSession
from app.services.auth_service_client import AuthServiceUnavailable, ResultRedemptionError
from app.services.mock_auth_service import MockAuthServiceClient


class TamperingMock(MockAuthServiceClient):
    """An auth service that returns a result for the WRONG account/transaction/binding."""

    def __init__(self, **overrides):
        super().__init__()
        self._overrides = overrides

    def redeem(self, result_handle):
        return dataclasses.replace(super().redeem(result_handle), **self._overrides)


class UnavailableMock(MockAuthServiceClient):
    def create_request(self, account_id, login_binding):
        raise AuthServiceUnavailable("down")


def _tx(mock):
    return mock.list_requests()[0]["tx_id"]


def _no_session(client):
    return client.cookies.get("gallifrey_session") is None


# ---- happy path -------------------------------------------------------------

def test_happy_path(client, mock_auth, login):
    login(client)
    assert client.get("/auth/status").json() == {"status": "PENDING"}

    mock_auth.approve(_tx(mock_auth))
    assert client.get("/auth/status").json() == {"status": "APPROVED"}

    r = client.post("/auth/complete")
    assert r.status_code == 200
    assert r.json() == {"status": "AUTHENTICATED", "redirect": "/dashboard"}

    dash = client.get("/dashboard")
    assert dash.status_code == 200
    assert "Welcome, demo_user" in dash.text


# ---- password alone is insufficient -----------------------------------------

def test_password_only_never_yields_a_session(client, login):
    login(client)
    assert client.get("/auth/status").json() == {"status": "PENDING"}

    # The browser cannot talk its way past the second factor.
    r = client.post("/auth/complete")
    assert r.status_code == 409
    assert r.json() == {"status": "PENDING"}

    assert _no_session(client)
    assert client.get("/dashboard").headers["location"] == "/login"


# ---- denied / expired -------------------------------------------------------

def test_denied_login_gets_no_session(client, mock_auth, login):
    login(client)
    mock_auth.deny(_tx(mock_auth))

    assert client.get("/auth/status").json() == {"status": "DENIED"}
    r = client.post("/auth/complete")
    assert r.status_code == 409
    assert r.json() == {"status": "DENIED"}
    assert _no_session(client)


def test_expired_at_auth_service_gets_no_session(client, mock_auth, login):
    login(client)
    # Reach into the mock to make its request look old.
    mock_auth._requests[_tx(mock_auth)].expires_at = utcnow(
    ) - timedelta(seconds=1)

    assert client.get("/auth/status").json() == {"status": "EXPIRED"}
    assert client.post("/auth/complete").status_code == 409
    assert _no_session(client)


def test_website_enforces_its_own_expiry(client, mock_auth, login, db_session_factory):
    login(client)
    mock_auth.approve(_tx(mock_auth))  # even an APPROVED request...

    with db_session_factory() as db:   # ...is useless once the PendingLogin expired
        pl = db.scalars(select(PendingLogin)).one()
        pl.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()

    r = client.get("/auth/status")
    assert r.status_code == 401
    assert r.json() == {"status": "EXPIRED"}
    assert client.post("/auth/complete").status_code == 401
    assert client.get("/auth/pending").headers["location"] == "/login"
    assert _no_session(client)


# ---- the result must belong to THIS login -----------------------------------

@pytest.mark.parametrize(
    "override",
    [
        {"login_binding": "x" * 43},
        {"tx_id": "tx_someone_else"},
        {"account_id": "999"},
    ],
    ids=["wrong_login_binding", "wrong_transaction", "wrong_account"],
)
def test_mismatched_result_is_rejected(make_client, login, override):
    mock = TamperingMock(**override)
    client = make_client(mock)
    login(client)
    mock.approve(_tx(mock))

    r = client.post("/auth/complete")
    assert r.status_code == 403
    assert r.json() == {"status": "ERROR"}
    assert _no_session(client)

    # The attempt is consumed: retrying does not help.
    assert client.post("/auth/complete").status_code == 401
    assert _no_session(client)


# ---- one-time redemption / replay -------------------------------------------

def test_result_can_only_be_redeemed_once(mock_auth):
    tx = mock_auth.create_request("1", "binding")
    mock_auth.approve(tx)
    handle = mock_auth.get_result(tx)

    assert mock_auth.redeem(handle).tx_id == tx  # first redemption succeeds
    with pytest.raises(ResultRedemptionError):   # second fails
        mock_auth.redeem(handle)
    assert mock_auth.get_result(tx) is None


def test_completed_pending_login_cannot_be_replayed(make_client, mock_auth, login):
    victim = make_client(mock_auth)
    login(victim)
    stolen_cookie = victim.cookies.get("gallifrey_pending", path="/auth")
    mock_auth.approve(_tx(mock_auth))
    assert victim.post("/auth/complete").status_code == 200

    # Someone replays the old pending cookie from another browser.
    attacker = make_client(mock_auth)
    attacker.cookies.set("gallifrey_pending", stolen_cookie,
                         domain="testserver", path="/auth")
    r = attacker.post("/auth/complete")
    assert r.status_code == 401
    assert _no_session(attacker)


# ---- failure and leakage ----------------------------------------------------

def test_login_fails_safely_when_auth_service_is_down(make_client, login, db_session_factory):
    client = make_client(UnavailableMock())
    r = login(client)
    assert r.status_code == 503
    assert client.cookies.get("gallifrey_pending") is None
    with db_session_factory() as db:
        assert db.scalars(select(PendingLogin)).all() == []


def test_browser_never_receives_internal_state(client, mock_auth, login, db_session_factory):
    login(client)
    tx = _tx(mock_auth)
    with db_session_factory() as db:
        binding = db.scalars(select(PendingLogin)).one().login_binding
    mock_auth.approve(tx)
    handle = mock_auth.get_result(tx)

    bodies = [
        client.get("/auth/pending").text,
        client.get("/auth/status").text,
        client.post("/auth/complete").text,
    ]
    for secret in (tx, binding, handle):
        assert all(secret not in body for body in bodies)
