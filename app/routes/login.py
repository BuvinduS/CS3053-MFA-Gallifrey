from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import COOKIE_SECURE, PENDING_COOKIE_NAME, PENDING_LOGIN_TTL_SECONDS
from app.db import get_db
from app.dependencies import get_auth_client
from app.services import pending_login_service, user_service
from app.services.auth_service_client import AuthServiceClient, AuthServiceError
from app.templating import templates

router = APIRouter()


@router.get("/login")
def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    auth_client: AuthServiceClient = Depends(get_auth_client),
):
    user = user_service.authenticate(db, username, password)
    if user is None:
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Incorrect username or password."}, status_code=401,
        )

    # SECURITY: a valid password is only the first factor. No WebSession here.
    try:
        token = pending_login_service.create_pending_login(
            db, user, auth_client)
    except AuthServiceError:
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "The second-step service is unavailable. Please try again shortly."},
            status_code=503,
        )

    response = RedirectResponse("/auth/pending", status_code=303)
    response.set_cookie(
        PENDING_COOKIE_NAME, token,
        max_age=PENDING_LOGIN_TTL_SECONDS,
        path="/auth",
        httponly=True, secure=COOKIE_SECURE, samesite="lax",
    )
    return response
