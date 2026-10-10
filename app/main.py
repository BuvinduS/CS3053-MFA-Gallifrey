from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.db import init_db
from app.routes import login, protected, auth


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Gallifrey RP Demo", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=Path(__file__).parent /
          "static"), name="static")
app.include_router(auth.router)
app.include_router(login.router)
app.include_router(protected.router)


@app.get("/")
def index():
    return RedirectResponse("/dashboard", status_code=303)
