import secrets

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.config import PENDING_COOKIE_NAME
from app.db import get_db
from app.dependencies import get_auth_client
from app.models import PendingLogin, User
from app.services import pending_login_service, session_service
from app.services.auth_service_client import (
    AuthServiceClient,
    AuthServiceError,
    AuthServiceUnavailable,
    AuthStatus,
    RedeemedResult,
    ResultRedemptionError,
)
from app.templating import templates

router = APIRouter(prefix="/auth")


def _json(status: str, code: int = 200) -> JSONResponse:
    # The browser only ever learns a status word, never auth-service internals.
    return JSONResponse({"status": status}, status_code=code,
                        headers={"Cache-Control": "no-store"})


@router.get("/pending")
def pending_page(request: Request, db: Session = Depends(get_db)):
    pending = pending_login_service.get_active_pending_login(
        db, request.cookies.get(PENDING_COOKIE_NAME)
    )
    if pending is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "pending.html", {})


@router.get("/status")
def status(
    request: Request,
    db: Session = Depends(get_db),
    auth_client: AuthServiceClient = Depends(get_auth_client),
):
    """Read-only: report the MFA status for this browser's pending login."""
    pending = pending_login_service.get_active_pending_login(
        db, request.cookies.get(PENDING_COOKIE_NAME)
    )
    if pending is None:
        return _json("EXPIRED", 401)  # missing, expired, or already used
    try:
        return _json(auth_client.get_status(pending.auth_tx_id).value)
    except AuthServiceUnavailable:
        return _json("UNAVAILABLE")
    except AuthServiceError:
        return _json("ERROR")


def _result_matches(pending: PendingLogin, result: RedeemedResult) -> bool:
    # SECURITY: "APPROVED" alone does not mean THIS browser may log in.
    # The redeemed result must belong to this account, this transaction and
    # this exact login attempt.
    return (
        result.account_id == str(pending.user_id)
        and result.tx_id == pending.auth_tx_id
        and secrets.compare_digest(
            result.login_binding.encode(), pending.login_binding.encode()
        )
    )


def _fail(db: Session, pending: PendingLogin) -> JSONResponse:
    pending.status = "FAILED"  # attempt is consumed; user must log in again
    db.commit()
    return _json("ERROR", 403)


@router.post("/complete")
def complete(
    request: Request,
    db: Session = Depends(get_db),
    auth_client: AuthServiceClient = Depends(get_auth_client),
):
    """Redeem the one-time result server-to-server and create the WebSession."""
    pending = pending_login_service.get_active_pending_login(
        db, request.cookies.get(PENDING_COOKIE_NAME)
    )
    if pending is None:
        return _json("EXPIRED", 401)

    try:
        # Never trust the browser: ask the auth service ourselves.
        current = auth_client.get_status(pending.auth_tx_id)
        if current != AuthStatus.APPROVED:
            return _json(current.value, 409)
        result_handle = auth_client.get_result(pending.auth_tx_id)
        if result_handle is None:
            raise ResultRedemptionError("No result available")
        result = auth_client.redeem(result_handle)  # one-time
    except ResultRedemptionError:
        return _fail(db, pending)
    except AuthServiceUnavailable:
        return _json("UNAVAILABLE", 503)
    except AuthServiceError:
        return _json("ERROR", 502)

    if not _result_matches(pending, result):
        return _fail(db, pending)

    user = db.get(User, pending.user_id)
    pending.status = "COMPLETED"  # this PendingLogin can never complete again
    token = session_service.create_session(db, user)  # commits both changes

    response = JSONResponse(
        {"status": "AUTHENTICATED", "redirect": "/dashboard"},
        headers={"Cache-Control": "no-store"},
    )
    session_service.set_session_cookie(response, token)
    response.delete_cookie(PENDING_COOKIE_NAME, path="/auth")
    return response
