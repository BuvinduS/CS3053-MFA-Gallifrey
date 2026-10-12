"""Interface between the website (Relying Party) and the authentication service.

This file is the API CONTRACT with the authentication-service team:

    create_request(account_id, login_binding, idempotency_key) -> tx_id
    get_status(tx_id)                         -> AuthStatus
    get_result(tx_id)                         -> result handle | None  (APPROVED only)
    redeem(result_handle, login_binding)      -> RedeemedResult         (ONE-TIME)

The website never trusts "APPROVED" on its own: after redeem() it checks that the
returned account, tx_id and login_binding match its own PendingLogin.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class AuthStatus(str, Enum):
    PENDING = "PENDING"
    CANCELLED = "CANCELLED"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    LOCKED = "LOCKED"


class AuthServiceError(Exception):
    """Base class for failures talking to the authentication service."""


class AuthServiceUnavailable(AuthServiceError):
    """Service unreachable or returned an unusable response."""


class AuthServiceRateLimited(AuthServiceError):
    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__("Authentication request rate limited")


class ResultRedemptionError(AuthServiceError):
    """Result unknown, already redeemed, or otherwise not redeemable."""


@dataclass(frozen=True)
class RedeemedResult:
    account_id: str
    tx_id: str
    login_binding: str


class AuthServiceClient(ABC):
    @abstractmethod
    def create_request(
        self,
        account_id: str,
        login_binding: str,
        idempotency_key: str | None = None,
    ) -> str: ...

    @abstractmethod
    def get_status(self, tx_id: str) -> AuthStatus: ...

    @abstractmethod
    def get_result(self, tx_id: str) -> str | None: ...

    @abstractmethod
    def redeem(self, result_handle: str, login_binding: str) -> RedeemedResult: ...
