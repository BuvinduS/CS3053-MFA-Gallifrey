from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import COOKIE_SECURE, SESSION_COOKIE_NAME, SESSION_TTL_MINUTES
from app.db import get_db
from app.services import session_service, user_service
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
):
    user = user_service.authenticate(db, username, password)
    if user is None:
        # Same message for unknown user and wrong password.
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Incorrect username or password."}, status_code=401,
        )

    # TEMPORARY (Stage 1 scaffolding): password alone creates a session.
    # Stage 2 replaces this with a PendingLogin so password alone is never enough.
    token = session_service.create_session(db, user)
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        max_age=SESSION_TTL_MINUTES * 60,
        httponly=True, secure=COOKIE_SECURE, samesite="lax",
    )
    return response
