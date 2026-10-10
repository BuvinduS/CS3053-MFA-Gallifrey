from app.services.auth_service_client import AuthServiceClient
from app.services.mock_auth_service import MockAuthServiceClient

# One shared instance so state survives between requests.
# To use the real service later, swap this for an HttpAuthServiceClient.
_mock_client = MockAuthServiceClient()


def get_auth_client() -> AuthServiceClient:
    return _mock_client


def get_mock_auth_client() -> MockAuthServiceClient:
    """Only used by the dev routes, which need the mock's approve/deny helpers."""
    return _mock_client
