"""Administrative API used by the dashboard (all routes under /admin/api)."""
from __future__ import annotations

import csv
import hmac
import io
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app import events, simulator
from app.config import settings
from app.detection import RULE_CATALOGUE
from app.gateway import client_ip
from app.ingest import ingest
from app.proxy import get_backend_client
from app.runtime import MODE_DESCRIPTIONS, MODES, runtime
from app.security.authorization import ownership
from app.security.rate_limit import admin_login_limiter, limiter

router = APIRouter(prefix="/admin/api", tags=["admin"])
SESSION_COOKIE = "fortress_session"

GATEWAY_RULES = [
    {"rule_id": "AUTH-001", "name": "Missing token", "category": "authentication", "mandatory": True, "status": 401},
    {"rule_id": "AUTH-002", "name": "Invalid token", "category": "authentication", "mandatory": True, "status": 401},
    {"rule_id": "AUTH-003", "name": "Expired token", "category": "authentication", "mandatory": True, "status": 401},
    {"rule_id": "AUTH-004", "name": "Invalid claims", "category": "authentication", "mandatory": True, "status": 401},
    {"rule_id": "AUTHZ-001", "name": "Object ownership violation", "category": "authorization", "mandatory": False, "status": 403},
    {"rule_id": "AUTHZ-002", "name": "Authorization unverifiable", "category": "authorization", "mandatory": True, "status": 503},
    {"rule_id": "RATE-001", "name": "Rate limit exceeded", "category": "rate_limit", "mandatory": False, "status": 429},
    {"rule_id": "REQ-001", "name": "Suspicious input", "category": "input_validation", "mandatory": False, "status": 400},
    {"rule_id": "REQ-002", "name": "Payload too large", "category": "input_validation", "mandatory": True, "status": 413},
]


# --------------------------------------------------------------------------
# session handling
# --------------------------------------------------------------------------
def _issue_session(username: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": username, "scope": "admin", "iat": now, "exp": now + timedelta(minutes=settings.session_ttl_minutes)},
        settings.admin_session_secret,
        algorithm="HS256",
    )


def require_admin(request: Request) -> str:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        claims = jwt.decode(token, settings.admin_session_secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Session expired")
    if claims.get("scope") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return claims["sub"]


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response):
    allowed, _, retry = admin_login_limiter.hit(f"admin-login:{client_ip(request)}", 10, 300)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Too many attempts. Retry in {retry}s",
                            headers={"Retry-After": str(retry)})
    user_ok = hmac.compare_digest(body.username.encode(), settings.admin_username.encode())
    pass_ok = hmac.compare_digest(body.password.encode(), settings.admin_password.encode())
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    response.set_cookie(
        SESSION_COOKIE,
        _issue_session(body.username),
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    return {"username": body.username}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
async def me(user: str = Depends(require_admin)):
    return {"username": user, "environment": settings.app_env}


# --------------------------------------------------------------------------
# dashboard data
# --------------------------------------------------------------------------
@router.get("/overview")
async def overview(_: str = Depends(require_admin)):
    data = await run_in_threadpool(events.overview)
    data["policy"] = runtime.snapshot()
    return data


@router.get("/timeline")
async def get_timeline(range: str = Query("60m", pattern="^(60m|6h|24h)$"), _: str = Depends(require_admin)):
    return await run_in_threadpool(events.timeline, range)


def _filters(origin, source, decision, classification, rule_id, min_severity, batch_id, q) -> dict:
    return {
        "origin": origin, "source": source, "decision": decision, "classification": classification,
        "rule_id": rule_id, "min_severity": min_severity, "batch_id": batch_id, "q": (q or "").strip() or None,
    }


@router.get("/events")
async def list_events(
    origin: str | None = Query(None, pattern="^(gateway|imported)$"),
    source: str | None = None,
    decision: str | None = None,
    classification: str | None = None,
    rule_id: str | None = None,
    min_severity: int | None = Query(None, ge=0, le=4),
    batch_id: int | None = None,
    q: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: str = Depends(require_admin),
):
    f = _filters(origin, source, decision, classification, rule_id, min_severity, batch_id, q)
    total, rows = await run_in_threadpool(events.query_events, f, limit, offset)
    return {"total": total, "limit": limit, "offset": offset, "items": rows}


@router.get("/events/export.csv")
async def export_events(
    origin: str | None = Query(None, pattern="^(gateway|imported)$"),
    source: str | None = None,
    decision: str | None = None,
    classification: str | None = None,
    min_severity: int | None = Query(None, ge=0, le=4),
    q: str | None = None,
    _: str = Depends(require_admin),
):
    f = _filters(origin, source, decision, classification, None, min_severity, None, q)
    cols = ["id", "created_at", "event_time", "origin", "source", "decision", "classification", "severity_label",
            "rule_id", "rule_name", "reason", "method", "path", "status_code", "client_ip", "username", "mode", "latency_ms"]

    def generate():
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for row in events.iter_events(f):
            writer.writerow(row)
            if buf.tell() > 65536:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
        yield buf.getvalue()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return StreamingResponse(generate(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="fortress-events-{stamp}.csv"'})


@router.get("/events/{event_id}")
async def event_detail(event_id: int, _: str = Depends(require_admin)):
    ev = await run_in_threadpool(events.get_event, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    return ev


@router.delete("/events")
async def clear_events(origin: str | None = Query(None, pattern="^(gateway|imported)$"), _: str = Depends(require_admin)):
    n = await run_in_threadpool(events.clear_events, origin)
    return {"deleted": n}


# --------------------------------------------------------------------------
# policy
# --------------------------------------------------------------------------
class SettingsBody(BaseModel):
    mode: str | None = Field(None, pattern="^(learning|monitor|enforce)$")
    rate_limit_requests: int | None = Field(None, ge=1, le=100000)
    rate_limit_window: int | None = Field(None, ge=1, le=86400)


@router.get("/settings")
async def get_settings(_: str = Depends(require_admin)):
    return {
        "policy": runtime.snapshot(),
        "modes": [{"id": m, "description": MODE_DESCRIPTIONS[m]} for m in MODES],
        "public_paths": list(settings.public_paths),
        "protected_resources": ownership.describe(),
        "gateway_rules": GATEWAY_RULES,
        "detection_rules": RULE_CATALOGUE,
        "backend_url": settings.backend_url,
        "max_body_bytes": settings.max_body_bytes,
        "ingest_push_enabled": bool(settings.ingest_token),
    }


@router.put("/settings")
async def update_settings(body: SettingsBody, _: str = Depends(require_admin)):
    snap = await run_in_threadpool(runtime.update, **body.model_dump())
    if body.rate_limit_requests is not None or body.rate_limit_window is not None:
        limiter.reset()
    return {"policy": snap}


@router.get("/profiles")
async def profiles(_: str = Depends(require_admin)):
    return {"items": await run_in_threadpool(events.list_profiles)}


@router.get("/health")
async def health(_: str = Depends(require_admin)):
    try:
        r = await get_backend_client().get("/health", timeout=3.0)
        backend = {"reachable": r.status_code == 200, "status": r.status_code}
    except Exception as exc:
        backend = {"reachable": False, "error": exc.__class__.__name__}
    return {"gateway": "ok", "backend": backend, "mode": runtime.mode}


# --------------------------------------------------------------------------
# log ingestion
# --------------------------------------------------------------------------
@router.post("/ingest/upload")
async def upload_logs(
    file: UploadFile = File(...),
    source: str = Form("auto"),
    _: str = Depends(require_admin),
):
    if source not in ("auto", "wazuh", "suricata", "modsecurity"):
        raise HTTPException(status_code=422, detail="Unsupported source")
    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_bytes // (1024 * 1024)} MB")
    if not content.strip():
        raise HTTPException(status_code=422, detail="File is empty")
    return await run_in_threadpool(ingest, content, file.filename or "upload.json", source, "upload")


@router.post("/ingest/push")
async def push_logs(request: Request, source: str = Query("auto")):
    """Machine-to-machine ingestion used by scripts/ship_logs.py (header: X-Ingest-Token)."""
    if not settings.ingest_token:
        raise HTTPException(status_code=404, detail="Push ingestion is disabled (set INGEST_TOKEN)")
    supplied = request.headers.get("x-ingest-token", "")
    if not hmac.compare_digest(supplied.encode(), settings.ingest_token.encode()):
        raise HTTPException(status_code=401, detail="Invalid ingest token")
    body = await request.body()
    if len(body) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Payload too large")
    name = request.headers.get("x-source-name", "push")
    return await run_in_threadpool(ingest, body, name, source, "push")


@router.get("/ingest/batches")
async def batches(_: str = Depends(require_admin)):
    return {"items": await run_in_threadpool(events.list_batches)}


# --------------------------------------------------------------------------
# attack lab & demo maintenance
# --------------------------------------------------------------------------
@router.get("/simulate")
async def list_scenarios(_: str = Depends(require_admin)):
    return {"items": [{"id": k, **v} for k, v in simulator.SCENARIOS.items()], "mode": runtime.mode}


@router.post("/simulate/{scenario}")
async def simulate(scenario: str, _: str = Depends(require_admin)):
    if scenario not in simulator.SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    return await simulator.run_scenario(scenario)


@router.post("/demo/reset")
async def reset_demo(_: str = Depends(require_admin)):
    try:
        r = await get_backend_client().post("/internal/reset",
                                            headers={"X-Gateway-Secret": settings.gateway_shared_secret}, timeout=5.0)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Backend unreachable: {exc.__class__.__name__}")
    limiter.reset()
    ownership.clear()
    return {"backend_status": r.status_code, "rate_limits_cleared": True}
