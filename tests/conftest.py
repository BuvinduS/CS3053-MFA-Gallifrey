import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.dependencies import get_auth_client
from app.main import app
from app.models import User
from app.services.mock_auth_service import MockAuthServiceClient
from app.services.user_service import hash_password

DEMO_USER = "demo_user"
DEMO_PASSWORD = "demo-password"


@pytest.fixture
def db_session_factory():
    """A fresh in-memory database per test, with the demo user."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    with factory() as db:
        db.add(User(username=DEMO_USER, password_hash=hash_password(DEMO_PASSWORD)))
        db.commit()
    yield factory
    engine.dispose()


@pytest.fixture
def make_client(db_session_factory):
    """Build a test client wired to the test DB and a given (mock) auth service."""
    def _make(auth_service):
        def override_db():
            db = db_session_factory()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_auth_client] = lambda: auth_service
        # https so Secure cookies are sent: we test the real production cookie config.
        return TestClient(app, base_url="https://testserver", follow_redirects=False)

    yield _make
    app.dependency_overrides.clear()


@pytest.fixture
def mock_auth():
    return MockAuthServiceClient()


@pytest.fixture
def client(make_client, mock_auth):
    return make_client(mock_auth)


@pytest.fixture
def login():
    def _login(client, password=DEMO_PASSWORD):
        return client.post("/login", data={"username": DEMO_USER, "password": password})
    return _login


@pytest.fixture
def full_login(login):
    """Password -> approve on the mock -> /auth/complete. Returns the complete response."""
    def _do(client, mock):
        login(client)
        mock.approve(mock.list_requests()[0]["tx_id"])
        return client.post("/auth/complete")
    return _do