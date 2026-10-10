import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.config import PENDING_LOGIN_TTL_SECONDS
from app.db import utcnow
from app.services.auth_service_client import (
    AuthServiceClient,
    AuthServiceError,
    AuthStatus,
    RedeemedResult,
    ResultRedemptionError,
)


@dataclass
class _Request:
    tx_id: str
    account_id: str
    login_binding: str
    expires_at: datetime
    status: AuthStatus = AuthStatus.PENDING
    result_handle: str | None = None
    redeemed: bool = False


class MockAuthServiceClient(AuthServiceClient):
    """In-memory stand-in for the real authentication service (demo only).

    approve()/deny()/list_requests() are development helpers that replace the
    phone. They are NOT part of the AuthServiceClient contract.
    """

    def __init__(self) -> None:
        self._requests: dict[str, _Request] = {}
        self._results: dict[str, str] = {}  # result handle -> tx_id

    # ---- contract methods -------------------------------------------------

    def create_request(self, account_id: str, login_binding: str) -> str:
        tx_id = "tx_" + secrets.token_hex(4)
        self._requests[tx_id] = _Request(
            tx_id=tx_id,
            account_id=account_id,
            login_binding=login_binding,
            expires_at=utcnow() + timedelta(seconds=PENDING_LOGIN_TTL_SECONDS),
        )
        return tx_id

    def get_status(self, tx_id: str) -> AuthStatus:
        return self._get(tx_id).status

    def get_result(self, tx_id: str) -> str | None:
        req = self._get(tx_id)
        if req.status == AuthStatus.APPROVED and not req.redeemed:
            return req.result_handle
        return None

    def redeem(self, result_handle: str) -> RedeemedResult:
        tx_id = self._results.get(result_handle)
        if tx_id is None:
            raise ResultRedemptionError("Unknown result")
        req = self._requests[tx_id]
        if req.redeemed:
            raise ResultRedemptionError("Result already redeemed")
        req.redeemed = True  # one-time: consumed on first successful redeem
        return RedeemedResult(req.account_id, req.tx_id, req.login_binding)

    # ---- development helpers ----------------------------------------------

    def approve(self, tx_id: str) -> bool:
        req = self._get(tx_id)
        if req.status != AuthStatus.PENDING:
            return False
        req.status = AuthStatus.APPROVED
        req.result_handle = secrets.token_urlsafe(32)
        self._results[req.result_handle] = tx_id
        return True

    def deny(self, tx_id: str) -> bool:
        req = self._get(tx_id)
        if req.status != AuthStatus.PENDING:
            return False
        req.status = AuthStatus.DENIED
        return True

    def list_requests(self) -> list[dict]:
        # login_binding is deliberately not exposed here.
        return [
            {
                "tx_id": r.tx_id,
                "account_id": r.account_id,
                "status": self._refresh(r).status.value,
                "expires_at": r.expires_at,
            }
            for r in reversed(list(self._requests.values()))
        ]

    # ---- internals ----------------------------------------------------------

    def _refresh(self, req: _Request) -> _Request:
        if req.status == AuthStatus.PENDING and utcnow() >= req.expires_at:
            req.status = AuthStatus.EXPIRED
        return req

    def _get(self, tx_id: str) -> _Request:
        req = self._requests.get(tx_id)
        if req is None:
            raise AuthServiceError(f"Unknown transaction {tx_id}")
        return self._refresh(req)
