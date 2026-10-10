def test_wrong_password_is_rejected(client, login):
    r = login(client, password="not-the-password")
    assert r.status_code == 401
    assert "Incorrect username or password." in r.text
    assert client.cookies.get("gallifrey_pending") is None
    assert client.cookies.get("gallifrey_session") is None


def test_unknown_user_gets_same_error_as_wrong_password(client, login):
    wrong_pw = login(client, password="nope")
    unknown = client.post(
        "/login", data={"username": "nobody", "password": "nope"})
    assert unknown.status_code == wrong_pw.status_code == 401
    assert "Incorrect username or password." in unknown.text


def test_valid_password_starts_pending_login_but_creates_no_session(client, login):
    r = login(client)
    assert r.status_code == 303
    assert r.headers["location"] == "/auth/pending"
    assert client.cookies.get("gallifrey_pending") is not None
    assert client.cookies.get("gallifrey_session") is None


def test_dashboard_requires_a_session(client):
    r = client.get("/dashboard")
    assert r.status_code == 303
    assert r.headers["location"] == "/login"
