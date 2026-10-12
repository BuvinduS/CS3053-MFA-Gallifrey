"""Enrollment endpoints (§13):

  POST /v1/enrollments                 – RP: create enrollment token
  POST /v1/enrollments/claim           – Mobile + token: submit public key
  POST /v1/enrollments/{id}/complete   – Mobile + proof: verify and activate
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth_service.db import get_db, utcnow
from auth_service.dependencies import get_rp
from auth_service.models.auth_account import AuthAccount
from auth_service.models.relying_party import RelyingParty
from auth_service.services import enrollment_service
from auth_service.services.enrollment_service import (
    EnrollmentError,
    EnrollmentNotFound,
    EnrollmentProofInvalid,
    EnrollmentTokenInvalid,
)

router = APIRouter(prefix="/v1/enrollments", tags=["enrollment"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class EnrollmentCreateRequest(BaseModel):
    rp_subject: str = Field(min_length=1, max_length=255)


class EnrollmentCreateResponse(BaseModel):
    enrollment_id: str
    enrollment_token: str  # bearer secret – return once only
    expires_in_seconds: int


class ClaimRequest(BaseModel):
    enrollment_token: str = Field(min_length=1, max_length=128)
    public_key_spki: str = Field(min_length=1, max_length=512)


class ClaimResponse(BaseModel):
    enrollment_id: str
    device_id: str
    challenge_nonce: str
    account_ref: str
    public_key_fingerprint: str


class CompleteRequest(BaseModel):
    signature: str = Field(min_length=1, max_length=256)


class CompleteResponse(BaseModel):
    device_id: str
    device_api_token: str  # scoped bearer – return once; store the hash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_or_create_account(db: Session, rp: "RelyingParty", rp_subject: str) -> AuthAccount:
    from sqlalchemy import select
    account = db.scalar(
        select(AuthAccount).where(
            AuthAccount.rp_id == rp.id,
            AuthAccount.rp_subject == rp_subject,
        )
    )
    if account is None:
        account = AuthAccount(
            rp_subject=rp_subject,
            rp_id=rp.id,
            created_at=utcnow(),
        )
        db.add(account)
        db.flush()
    return account


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("", status_code=status.HTTP_201_CREATED, response_model=EnrollmentCreateResponse)
def create_enrollment(
    body: EnrollmentCreateRequest,
    rp: RelyingParty = Depends(get_rp),
    db: Session = Depends(get_db),
):
    """RP backend: create a one-time enrollment token for a user."""
    account = _get_or_create_account(db, rp, body.rp_subject)
    raw_token = enrollment_service.create_enrollment_token(
        db, rp_id=rp.id, account_id=account.id
    )
    # Find the enrollment we just created to get its ID.
    from sqlalchemy import select
    import hashlib
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    from auth_service.models.enrollment import Enrollment
    enrollment = db.scalar(select(Enrollment).where(Enrollment.token_hash == token_hash))
    from auth_service.config import ENROLLMENT_TTL_SECONDS
    return EnrollmentCreateResponse(
        enrollment_id=enrollment.id,
        enrollment_token=raw_token,
        expires_in_seconds=ENROLLMENT_TTL_SECONDS,
    )


@router.post("/claim", status_code=status.HTTP_200_OK, response_model=ClaimResponse)
def claim_enrollment(
    body: ClaimRequest,
    db: Session = Depends(get_db),
):
    """Mobile: submit public key with the enrollment token to get a challenge."""
    try:
        enrollment, challenge_nonce, device = enrollment_service.claim_enrollment(
            db,
            enrollment_token=body.enrollment_token,
            public_key_spki_b64url=body.public_key_spki,
        )
    except EnrollmentTokenInvalid as exc:
        raise HTTPException(status.HTTP_410_GONE, detail=str(exc))
    except EnrollmentError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return ClaimResponse(
        enrollment_id=enrollment.id,
        device_id=enrollment.device_id,
        challenge_nonce=challenge_nonce,
        account_ref=enrollment.account_id,
        public_key_fingerprint=enrollment_service.fingerprint_b64url(
            device.public_key_spki
        ),
    )


@router.post("/{enrollment_id}/complete", response_model=CompleteResponse)
def complete_enrollment(
    enrollment_id: str,
    body: CompleteRequest,
    db: Session = Depends(get_db),
):
    """Mobile: prove key possession; receive the scoped device API token."""
    try:
        device, raw_token = enrollment_service.complete_enrollment(
            db,
            enrollment_id=enrollment_id,
            signature_b64url=body.signature,
        )
    except EnrollmentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Enrollment not found")
    except EnrollmentTokenInvalid:
        raise HTTPException(status.HTTP_410_GONE, detail="Enrollment expired")
    except EnrollmentProofInvalid:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Proof invalid")
    except EnrollmentError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return CompleteResponse(
        device_id=device.id,
        device_api_token=raw_token,
    )
