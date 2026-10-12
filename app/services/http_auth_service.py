"""HTTP adapter for the separately deployed authentication service."""
import secrets
from math import ceil
from urllib.parse import quote, urlsplit

import httpx

from app.services.auth_service_client import (
    AuthServiceClient,
    AuthServiceError,
    AuthServiceRateLimited,
    AuthServiceUnavailable,
    AuthStatus,
    RedeemedResult,
    ResultRedemptionError,
)


class HttpAuthServiceClient(AuthServiceClient):
    def __init__(
        self,
        base_url: str,
        client_secret: str,
        *,
        timeout_seconds: float = 3.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or (parsed.scheme != "https" and parsed.hostname not in local_hosts)
        ):
            raise ValueError("Auth service URL must use HTTPS except on localhost")
        if not client_secret:
            raise ValueError("RP client secret is required")

        self._client = httpx.Client(
            base_url=base_url.rstrip("/") + "/",
            headers={"Authorization": f"Bearer {client_secret}"},
            timeout=timeout_seconds,
            follow_redirects=False,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def _send(self, method: str, path: str, **kwargs) -> httpx.Response:
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.RequestError as exc:
            raise AuthServiceUnavailable("Authentication service unavailable") from exc
        if response.status_code >= 500:
            raise AuthServiceUnavailable("Authentication service unavailable")
        return response

    @staticmethod
    def _read_payload(response: httpx.Response) -> dict:
        if not response.is_success:
            raise AuthServiceError("Authentication service rejected the request")
        try:
            payload = response.json()
        except ValueError as exc:
            raise AuthServiceUnavailable("Invalid authentication service response") from exc
        if not isinstance(payload, dict):
            raise AuthServiceUnavailable("Invalid authentication service response")
        return payload

    def create_request(
        self,
        account_id: str,
        login_binding: str,
        idempotency_key: str | None = None,
    ) -> str:
        key = idempotency_key or secrets.token_urlsafe(24)
        kwargs = {
            "json": {
                "rp_subject": account_id,
                "login_binding": login_binding,
            },
            "headers": {"Idempotency-Key": key},
        }

        for attempt in range(2):
            try:
                response = self._client.post("v1/auth-requests", **kwargs)
            except httpx.RequestError as exc:
                if attempt == 0:
                    continue
                raise AuthServiceUnavailable(
                    "Authentication service unavailable"
                ) from exc
            if response.status_code >= 500:
                if attempt == 0:
                    continue
                raise AuthServiceUnavailable("Authentication service unavailable")
            if response.status_code == 429:
                retry_after = response.headers.get("retry-after", "60")
                try:
                    retry_after_seconds = max(1, ceil(float(retry_after)))
                except (OverflowError, ValueError):
                    retry_after_seconds = 60
                raise AuthServiceRateLimited(retry_after_seconds)
            payload = self._read_payload(response)
            transaction_id = payload.get("transaction_id")
            if not isinstance(transaction_id, str) or not transaction_id:
                raise AuthServiceUnavailable("Invalid authentication service response")
            return transaction_id
        raise AuthServiceUnavailable("Authentication service unavailable")

    def get_status(self, tx_id: str) -> AuthStatus:
        payload = self._read_payload(
            self._send("GET", f"v1/rp/requests/{quote(tx_id, safe='')}")
        )
        try:
            return AuthStatus(payload["status"])
        except (KeyError, ValueError) as exc:
            raise AuthServiceUnavailable("Invalid authentication service status") from exc

    def get_result(self, tx_id: str) -> str | None:
        payload = self._read_payload(
            self._send("POST", f"v1/rp/requests/{quote(tx_id, safe='')}/result")
        )
        result_code = payload.get("result_code")
        if result_code is not None and not isinstance(result_code, str):
            raise AuthServiceUnavailable("Invalid authentication service result")
        return result_code

    def redeem(self, result_handle: str, login_binding: str) -> RedeemedResult:
        response = self._send(
            "POST",
            "v1/rp/results/redeem",
            json={"result_code": result_handle, "login_binding": login_binding},
        )
        if not response.is_success:
            raise ResultRedemptionError("Authentication result could not be redeemed")
        try:
            payload = response.json()
            return RedeemedResult(
                account_id=payload["account_id"],
                tx_id=payload["transaction_id"],
                login_binding=payload["login_binding"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthServiceUnavailable("Invalid authentication service result") from exc
