# Gallifrey: MFA for Visually Impaired Users

## Authentication service

The authentication backend runs separately from the demonstration website. It
uses SQLite for local development and can use PostgreSQL with
`AUTH_DATABASE_URL=postgresql+psycopg://...`.

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

if [ ! -f .env ]; then
  printf 'RP_CLIENT_SECRET=%s\nRESULT_ENCRYPTION_KEY=%s\n' \
    "$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" \
    "$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" > .env
fi
set -a
source .env
set +a

python -m scripts.seed_auth
uvicorn auth_service.main:app --reload --port 8001
```

The API schema is available at `http://127.0.0.1:8001/docs`. Keep the `.env`
values stable while the service is running. The RP secret authenticates backend
calls, and the result-encryption key protects short-lived approval codes.
The Uvicorn command is for local development; connect mobile devices through
an HTTPS reverse proxy.

## Connect the demonstration website

From the repository root in a second terminal, use the same RP secret as the authentication service:

```sh
set -a
source .env
set +a
export AUTH_SERVICE_URL=http://127.0.0.1:8001
uvicorn app.main:app --reload --port 8000
```

The website uses the real HTTP adapter by default. Its RP subject is the
website user's ID; the authentication service must have an enrolled device
for that subject before login can complete. For the mock-only demo, use
`DEV_MODE=true COOKIE_SECURE=false uvicorn app.main:app --reload --port 8000`;
never enable `DEV_MODE` outside local development.

Authentication request creation is idempotent and limited to three requests
per account and ten per source IP in a five-minute window. The service returns
`429` with `Retry-After` when a limit is reached.

## Verification

Run the authentication backend tests, then the complete project suite:

```sh
python -m pytest tests/auth_service -q
python -m pytest -q
```
