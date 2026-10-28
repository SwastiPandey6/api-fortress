"""API Fortress gateway application.

Routes owned by the gateway:
    /dashboard           security console (static single-page app)
    /admin/api/*         administrative API (session-protected)
    /gateway/health      liveness probe
Every other path is evaluated by the security pipeline and, if permitted,
forwarded to the protected API (BACKEND_URL).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import admin, gateway
from app.config import settings
from app.database import init_db
from app.proxy import close_backend_client
from app.runtime import runtime

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("api_fortress")

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate()
    init_db()
    runtime.load()
    log.info("API Fortress gateway started | mode=%s backend=%s env=%s", runtime.mode, settings.backend_url, settings.app_env)
    yield
    await close_backend_client()


app = FastAPI(
    title="API Fortress Gateway",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/gateway/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/gateway/openapi.json",
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith(("/dashboard", "/admin")):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        )
        if request.url.path.startswith("/admin"):
            response.headers.setdefault("Cache-Control", "no-store")
    return response


app.include_router(admin.router)
app.mount("/dashboard/static", StaticFiles(directory=DASHBOARD_DIR / "static"), name="dashboard-static")


@app.get("/gateway/health", include_in_schema=False)
async def health():
    return {"status": "ok", "mode": runtime.mode}


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse("/dashboard")


@app.get("/dashboard", include_in_schema=False)
@app.get("/dashboard/", include_in_schema=False)
async def dashboard():
    return FileResponse(DASHBOARD_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.api_route("/{full_path:path}", methods=PROXY_METHODS, include_in_schema=False)
async def proxy_entry(full_path: str, request: Request):
    return await gateway.handle(request)
