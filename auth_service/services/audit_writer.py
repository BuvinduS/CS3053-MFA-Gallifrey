"""Audit writer – records sanitized security events (mypart.md §11).

Call write() from any service; it never raises (best-effort).
Secrets (patterns, passwords, keys, tokens) must never appear in metadata.
"""
import json
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from auth_service.db import utcnow
from auth_service.models.audit_event import AuditEvent

logger = logging.getLogger(__name__)


def write(
    db: Session,
    event_type: str,
    *,
    transaction_id: str | None = None,
    actor: str | None = None,
    metadata: dict | None = None,
) -> None:
    """Append a sanitized audit record.  Never logs secrets."""
    try:
        db.add(AuditEvent(
            transaction_id=transaction_id,
            event_type=event_type,
            actor=actor,
            metadata_json=json.dumps(metadata) if metadata else None,
            created_at=utcnow(),
        ))
        db.flush()  # include in the caller's transaction
    except Exception:  # noqa: BLE001
        logger.exception("AuditWriter failed – event lost: %s", event_type)
