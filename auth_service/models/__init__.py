"""Authentication-service ORM models.

Design decisions (from mypart.md §6):
  - UUID primary keys – avoids sequential / enumerable IDs in external APIs.
  - RegisteredDevice.public_key_spki stores a DER SubjectPublicKeyInfo encoded
    as base64url (no padding) – matches the Android/Python signing contract.
  - AuthTransaction.challenge_nonce is generated fresh per request.
  - attempt_count is [0, 3]; a partial unique index enforces one ACTIVE device
    per account.
  - AttemptEvent.event_id (client-supplied UUID) provides idempotency so that
    a retried delivery cannot increment the count twice.
  - AuthResult stores the code_hash and a short-lived encrypted copy for safe
    RP retries; the raw code is never persisted in plaintext.
"""

from auth_service.models.auth_account import AuthAccount
from auth_service.models.relying_party import RelyingParty
from auth_service.models.registered_device import RegisteredDevice
from auth_service.models.auth_transaction import AuthTransaction
from auth_service.models.auth_request_event import AuthRequestEvent
from auth_service.models.attempt_event import AttemptEvent
from auth_service.models.auth_result import AuthResult
from auth_service.models.audit_event import AuditEvent
from auth_service.models.enrollment import Enrollment

__all__ = [
    "AuthAccount",
    "RelyingParty",
    "RegisteredDevice",
    "AuthTransaction",
    "AuthRequestEvent",
    "AttemptEvent",
    "AuthResult",
    "AuditEvent",
    "Enrollment",
]
