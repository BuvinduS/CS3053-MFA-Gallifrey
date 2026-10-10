import hashlib
from datetime import timedelta

from sqlalchemy import select

from app.db import utcnow
from app.models import WebSession


def _session_cookie_attrs(response):
    for header in response.headers.get_list("set-cookie"):
        if header.startswith("gallifrey_session="):
            return [part.strip().lower() for part in header.split(";")[1:]]
    raise AssertionError("no session cookie was set")


def test_session_cookie_is_secure_httponly_samesite_lax(client, mock_auth, full_login):
    attrs = _session_cookie_attrs(full_login(client, mock_auth))
    assert "httponly" in attrs
    assert "secure" in attrs
    assert "samesite=lax" in attrs


def test_only_a_hash_of_the_token_is_stored(client, mock_auth, full_login, db_session_factory):
    full_login(client, mock_auth)
    token = client.cookies.get("gallifrey_session")
    with db_session_factory() as db:
        ws = db.scalars(select(WebSession)).one()
        assert ws.token_hash != token
        assert ws.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert ws.expires_at > ws.authenticated_at


def test_logout_invalidates_session_server_side(make_client, mock_auth, full_login):
    client = make_client(mock_auth)
    full_login(client, mock_auth)
    token = client.cookies.get("gallifrey_session")
    assert client.get("/dashboard").status_code == 200

    assert client.post("/logout").status_code == 303
    assert client.get("/dashboard").status_code == 303

    # Even someone who kept the old cookie value is refused.
    other = make_client(mock_auth)
    other.cookies.set("gallifrey_session", token, domain="testserver")
    assert other.get("/dashboard").status_code == 303


def test_expired_session_is_rejected(client, mock_auth, full_login, db_session_factory):
    full_login(client, mock_auth)
    with db_session_factory() as db:
        ws = db.scalars(select(WebSession)).one()
        ws.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert client.get("/dashboard").status_code == 303
