from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import PENDING_COOKIE_NAME
from app.db import get_db
from app.services import pending_login_service
from app.templating import templates

router = APIRouter(prefix="/auth")


@router.get("/pending")
def pending_page(request: Request, db: Session = Depends(get_db)):
    pending = pending_login_service.get_active_pending_login(
        db, request.cookies.get(PENDING_COOKIE_NAME)
    )
    if pending is None:
        # No valid pending login (never logged in, or it expired): start over.
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "pending.html", {})
