import httpx
import pytest

from app.services.auth_service_client import (
    AuthServiceRateLimited,
    AuthServiceUnavailable,
    AuthStatus,
    ResultRedemptionError,
)
from app.services.http_auth_service import HttpAuthServiceClient


def test_http_client_calls_auth_service_contract():
    seen = []

    def handle(request):
        seen.append(request)
        if request.url.path == "/v1/auth-requests":
            return httpx.Response(201, json={"transaction_id": "tx-123"})
        if request.url.path == "/v1/rp/requests/tx-123":
            return httpx.Response(200, json={"status": "APPROVED"})
        if request.url.path == "/v1/rp/requests/tx-123/result":
            return httpx.Response(200, json={"result_code": "one-time-code"})
        if request.url.path == "/v1/rp/results/redeem":
            return httpx.Response(
                200,
                json={
                    "account_id": "42",
                    "transaction_id": "tx-123",
                    "login_binding": "login-binding",
                },
            )
        return httpx.Response(404, json={"detail": "not found"})

    client = HttpAuthServiceClient(
        "https://auth.example.test",
        "rp-secret",
        transport=httpx.MockTransport(handle),
    )
    try:
        assert client.create_request("42", "login-binding", "request-1") == "tx-123"
        assert client.get_status("tx-123") is AuthStatus.APPROVED
        assert client.get_result("tx-123") == "one-time-code"
        result = client.redeem("one-time-code", "login-binding")
    finally:
        client.close()

    assert result.account_id == "42"
    assert result.tx_id == "tx-123"
    assert result.login_binding == "login-binding"
    assert all(request.headers["authorization"] == "Bearer rp-secret" for request in seen)
    assert seen[0].headers["idempotency-key"] == "request-1"
    assert httpx.Request(
        "POST", "https://auth.example.test/v1/rp/results/redeem"
    ).url == seen[-1].url
    assert seen[-1].read() == b'{"result_code":"one-time-code","login_binding":"login-binding"}'


def test_http_client_retries_creation_with_same_idempotency_key():
    keys = []

    def handle(request):
        keys.append(request.headers["idempotency-key"])
        if len(keys) == 1:
            raise httpx.ConnectError("temporary connection failure", request=request)
        return httpx.Response(201, json={"transaction_id": "tx-retried"})

    client = HttpAuthServiceClient(
        "https://auth.example.test",
        "rp-secret",
        transport=httpx.MockTransport(handle),
    )
    try:
        transaction_id = client.create_request("42", "binding", "retry-key")
    finally:
        client.close()

    assert transaction_id == "tx-retried"
    assert keys == ["retry-key", "retry-key"]


def test_http_client_requires_tls_for_non_local_service():
    with pytest.raises(ValueError, match="HTTPS"):
        HttpAuthServiceClient("http://auth.example.test", "rp-secret")


def test_http_client_treats_failed_redemption_as_one_time_error():
    client = HttpAuthServiceClient(
        "https://auth.example.test",
        "rp-secret",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(409, json={"detail": "Already redeemed"})
        ),
    )
    try:
        with pytest.raises(ResultRedemptionError):
            client.redeem("used-code", "binding")
    finally:
        client.close()


def test_http_client_reports_network_errors_as_unavailable():
    client = HttpAuthServiceClient(
        "https://auth.example.test",
        "rp-secret",
        transport=httpx.MockTransport(
            lambda request: (_ for _ in ()).throw(
                httpx.ConnectError("offline", request=request)
            )
        ),
    )
    try:
        with pytest.raises(AuthServiceUnavailable):
            client.get_status("tx-123")
    finally:
        client.close()


def test_http_client_preserves_rate_limit_retry_after():
    client = HttpAuthServiceClient(
        "https://auth.example.test",
        "rp-secret",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                429,
                headers={"Retry-After": "27"},
                json={"detail": "Too many authentication requests"},
            )
        ),
    )
    try:
        with pytest.raises(AuthServiceRateLimited) as error:
            client.create_request("42", "binding", "rate-key")
    finally:
        client.close()

    assert error.value.retry_after_seconds == 27
