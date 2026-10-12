from app.config import AUTH_SERVICE_URL, DEV_MODE, RP_CLIENT_SECRET
from app.services.auth_service_client import AuthServiceClient
from app.services.http_auth_service import HttpAuthServiceClient
from app.services.mock_auth_service import MockAuthServiceClient

# One shared development mock and one lazily initialized service client.
_mock_client = MockAuthServiceClient()
_http_client: HttpAuthServiceClient | None = None


def get_auth_client() -> AuthServiceClient:
    global _http_client
    if DEV_MODE:
        return _mock_client
    if _http_client is None:
        _http_client = HttpAuthServiceClient(
            AUTH_SERVICE_URL,
            RP_CLIENT_SECRET,
        )
    return _http_client


def get_mock_auth_client() -> MockAuthServiceClient:
    """Only used by the dev routes, which need the mock's approve/deny helpers."""
    return _mock_client
