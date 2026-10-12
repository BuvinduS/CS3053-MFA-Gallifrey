"""Authentication service FastAPI application entry point."""
from contextlib import asynccontextmanager
from ipaddress import ip_address

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from auth_service.db import init_db
from auth_service.routes import auth_requests, enrollments, rp_routes


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Gallifrey Authentication Service",
    description=(
        "Central authentication backend: nonce generation, "
        "ECDSA verification, transaction state, audit logging."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(enrollments.router)
app.include_router(auth_requests.router)
app.include_router(rp_routes.router)


@app.middleware("http")
async def require_https_for_nonlocal_clients(request: Request, call_next):
    client_host = request.client.host if request.client else ""
    try:
        local_client = ip_address(client_host).is_loopback
    except ValueError:
        local_client = client_host == "testclient"
    if request.url.scheme != "https" and not local_client:
        return JSONResponse(
            {"detail": "HTTPS is required"},
            status_code=426,
            headers={"Cache-Control": "no-store"},
        )
    return await call_next(request)


@app.middleware("http")
async def prevent_response_caching(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Generic error handlers – never leak internals to callers
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    import logging
    logging.getLogger(__name__).exception("Unhandled error: %s", exc)
    return JSONResponse(
        {"detail": "Internal server error"},
        status_code=500,
        headers={"Cache-Control": "no-store"},
    )
