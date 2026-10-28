"""Request evaluation pipeline.

Order of checks for every proxied request:

1. Payload size            (mandatory)
2. Content inspection      (policy)      REQ-001
3. Authentication (JWT)    (mandatory)   AUTH-00x
4. Rate limiting           (policy)      RATE-001
5. Object ownership        (policy)      AUTHZ-001

Mandatory violations are blocked in every mode. Policy violations are blocked
in Enforce mode, recorded as "flagged" in Monitor mode, and recorded as
"observed" in Learning mode.
"""
from __future__ import annotations

import json
import logging
import time
import uuid

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app import events
from app.config import settings
from app.proxy import forward, get_backend_client
from app.runtime import runtime
from app.security import Violation
from app.security.authorization import ownership
from app.security.inspection import inspect_request
from app.security.jwt_auth import validate_authorization_header
from app.security.rate_limit import limiter

log = logging.getLogger("api_fortress.gateway")


def client_ip(request: Request) -> str:
    if settings.trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def is_public(path: str) -> bool:
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in settings.public_paths)


async def handle(request: Request) -> Response:
    started = time.perf_counter()
    request_id = uuid.uuid4().hex[:16]
    mode = runtime.mode
    path = request.url.path
    method = request.method.upper()
    ip = client_ip(request)
    body = await request.body()
    violations: list[Violation] = []
    claims: dict | None = None

    # 1. payload size
    if len(body) > settings.max_body_bytes:
        violations.append(
            Violation("REQ-002", "Payload too large", f"Body of {len(body)} bytes exceeds {settings.max_body_bytes}",
                      413, 2, "payload_size", mandatory=True)
        )

    # 2. content inspection
    if not violations:
        raw_path = request.scope.get("raw_path", path.encode()).decode("latin-1")
        found = inspect_request(raw_path, request.url.query, body, request.headers.get("content-type", ""))
        if found:
            violations.append(found)

    # 3. authentication
    if not any(v.mandatory for v in violations) and not is_public(path):
        claims, auth_violation = validate_authorization_header(request.headers.get("authorization"))
        if auth_violation:
            violations.append(auth_violation)

    # 4. rate limiting (identity = token subject when known, otherwise IP)
    identity = f"user:{claims['sub']}" if claims else f"ip:{ip}"
    allowed, _remaining, retry_after = limiter.hit(identity, runtime.rate_limit_requests, runtime.rate_limit_window)
    if not allowed:
        violations.append(
            Violation("RATE-001", "Rate limit exceeded",
                      f"{identity} exceeded {runtime.rate_limit_requests} requests per {runtime.rate_limit_window}s",
                      429, 2, "rate_limit", headers={"Retry-After": str(retry_after)})
        )

    # 5. object-level authorization
    if claims and not any(v.mandatory for v in violations):
        authz = await ownership.check(method, path, claims, get_backend_client())
        if authz:
            violations.append(authz)

    # ---- decision ---------------------------------------------------------
    mandatory = [v for v in violations if v.mandatory]
    if mandatory:
        blocking = mandatory[0]
    elif violations and mode == "enforce":
        blocking = max(violations, key=lambda v: v.severity)
    else:
        blocking = None

    username = claims.get("sub") if claims else None
    primary = blocking or (max(violations, key=lambda v: v.severity) if violations else None)

    if blocking:
        decision = "blocked"
        response: Response = JSONResponse(
            {
                "error": blocking.name.lower().replace(" ", "_"),
                "rule": blocking.rule_id,
                "message": blocking.reason,
                "request_id": request_id,
            },
            status_code=blocking.status_code,
            headers={**blocking.headers, "X-Request-ID": request_id, "X-Fortress-Decision": "blocked"},
        )
    else:
        response, upstream_ok = await forward(request, body, ip, request_id, claims)
        if not upstream_ok:
            decision = "error"
        elif violations:
            decision = "flagged" if mode == "monitor" else "observed"
        else:
            decision = "allowed"
        response.headers["X-Fortress-Decision"] = decision

    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    record = {
        "event_type": "request",
        "decision": decision,
        "classification": primary.category if primary else ("upstream_error" if decision == "error" else "none"),
        "rule_id": primary.rule_id if primary else ("UPSTREAM-001" if decision == "error" else None),
        "rule_name": primary.name if primary else ("Upstream unavailable" if decision == "error" else None),
        "reason": primary.reason if primary else None,
        "matches": json.dumps([v.as_dict() for v in violations]),
        "severity": primary.severity if primary else (1 if decision == "error" else 0),
        "mode": mode,
        "request_id": request_id,
        "method": method,
        "path": (path + (f"?{request.url.query}" if request.url.query else ""))[:2000],
        "status_code": response.status_code,
        "latency_ms": latency_ms,
        "client_ip": ip,
        "username": username,
        "raw": json.dumps(
            {
                "user_agent": request.headers.get("user-agent"),
                "content_type": request.headers.get("content-type"),
                "body_bytes": len(body),
                "violations": [v.as_dict() for v in violations],
            }
        ),
    }
    try:
        await run_in_threadpool(events.record_gateway_event, record)
        if mode == "learning" and decision != "blocked":
            await run_in_threadpool(events.record_profile, method, path, username, response.status_code, len(body))
    except Exception:  # never fail a request because logging failed
        log.exception("failed to record gateway event")

    return response
