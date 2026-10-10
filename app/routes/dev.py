"""DEVELOPMENT ONLY: stands in for the phone. Mounted only when DEV_MODE=true."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from app.dependencies import get_mock_auth_client
from app.services.mock_auth_service import MockAuthServiceClient
from app.templating import templates

router = APIRouter(prefix="/dev/mfa")


@router.get("")
def list_requests(request: Request, mock: MockAuthServiceClient = Depends(get_mock_auth_client)):
    return templates.TemplateResponse(
        request, "dev_mfa.html", {"requests": mock.list_requests()}
    )


@router.post("/{tx_id}/approve")
def approve(tx_id: str, mock: MockAuthServiceClient = Depends(get_mock_auth_client)):
    mock.approve(tx_id)
    return RedirectResponse("/dev/mfa", status_code=303)


@router.post("/{tx_id}/deny")
def deny(tx_id: str, mock: MockAuthServiceClient = Depends(get_mock_auth_client)):
    mock.deny(tx_id)
    return RedirectResponse("/dev/mfa", status_code=303)
