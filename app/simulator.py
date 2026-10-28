"""Attack lab: controlled, authorised test scenarios run against this gateway.

Every scenario sends real HTTP requests through the gateway, so the resulting
decisions appear in the dashboard exactly like external traffic.
"""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt

from app.config import settings
from app.runtime import runtime

DEMO_USERS = {
    "alice": "Alice@123",
    "bob": "Bob@123",
    "mallory": "Mallory@123",
}

SCENARIOS = {
    "legitimate": {
        "title": "Legitimate access",
        "description": "Alice signs in and reads her own record (101).",
        "rules": [],
    },
    "bola": {
        "title": "Broken object level authorization",
        "description": "Alice uses a valid token to request Bob's record (202) and modify it.",
        "rules": ["AUTHZ-001"],
    },
    "missing_token": {
        "title": "Missing token",
        "description": "A request to a protected record without an Authorization header.",
        "rules": ["AUTH-001"],
    },
    "forged_token": {
        "title": "Forged and unsigned tokens",
        "description": "Tokens signed with an attacker key, with alg=none, and with a tampered payload.",
        "rules": ["AUTH-002"],
    },
    "expired_token": {
        "title": "Expired token",
        "description": "A correctly signed token whose expiry is in the past.",
        "rules": ["AUTH-003"],
    },
    "injection": {
        "title": "Injection payloads",
        "description": "SQL injection, XSS and path traversal payloads in the query string and body.",
        "rules": ["REQ-001"],
    },
    "rate_limit": {
        "title": "Request flood",
        "description": "Mallory sends requests beyond the configured rate limit.",
        "rules": ["RATE-001"],
    },
}

_client_override: httpx.AsyncClient | None = None


def set_client(client: httpx.AsyncClient | None) -> None:
    global _client_override
    _client_override = client


def _client() -> httpx.AsyncClient:
    if _client_override is not None:
        return _client_override
    return httpx.AsyncClient(base_url=settings.self_url, timeout=15.0)


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _expected(code_when_blocked: int, mandatory: bool) -> int:
    if mandatory or runtime.mode == "enforce":
        return code_when_blocked
    return 200


class Run:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.steps: list[dict] = []

    async def login(self, user: str) -> str | None:
        r = await self.client.post("/auth/login", json={"username": user, "password": DEMO_USERS[user]},
                                   headers={"User-Agent": "api-fortress-attack-lab"})
        self._step(f"Sign in as {user}", "POST", "/auth/login", r, [200])
        return r.json().get("access_token") if r.status_code == 200 else None

    async def call(self, label, method, path, expected, token=None, **kw):
        headers = {"User-Agent": "api-fortress-attack-lab", **kw.pop("headers", {})}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        r = await self.client.request(method, path, headers=headers, **kw)
        self._step(label, method, path, r, expected if isinstance(expected, list) else [expected])
        return r

    def _step(self, label, method, path, r: httpx.Response, expected: list[int]) -> None:
        try:
            body = r.json()
        except ValueError:
            body = None
        self.steps.append(
            {
                "label": label,
                "method": method,
                "path": path,
                "status": r.status_code,
                "expected": expected,
                "passed": r.status_code in expected,
                "decision": r.headers.get("x-fortress-decision"),
                "rule": body.get("rule") if isinstance(body, dict) else None,
                "message": (body.get("message") or body.get("detail")) if isinstance(body, dict) else None,
            }
        )


async def run_scenario(name: str) -> dict:
    if name not in SCENARIOS:
        raise KeyError(name)
    started = time.perf_counter()
    client = _client()
    owns_client = client is not _client_override
    run = Run(client)
    try:
        if name == "legitimate":
            tok = await run.login("alice")
            await run.call("Read own record 101", "GET", "/records/101", 200, tok)
            await run.call("List own records", "GET", "/records", 200, tok)

        elif name == "bola":
            tok = await run.login("alice")
            exp = _expected(403, mandatory=False)
            await run.call("Read Bob's record 202", "GET", "/records/202", exp, tok)
            await run.call("Overwrite Bob's record 202", "PUT", "/records/202", exp, tok,
                           json={"title": "pwned", "content": "modified by alice"})

        elif name == "missing_token":
            await run.call("Read record without a token", "GET", "/records/101", 401)
            await run.call("Malformed Authorization header", "GET", "/records/101", 401,
                           headers={"Authorization": "Token abc"})

        elif name == "forged_token":
            now = datetime.now(timezone.utc)
            payload = {"sub": "alice", "role": "admin", "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
                       "iat": now, "exp": now + timedelta(minutes=10)}
            forged = jwt.encode(payload, "attacker-controlled-secret-0123456789abcdef", algorithm="HS256")
            await run.call("Token signed with attacker key", "GET", "/records/202", 401, forged)
            unsigned_payload = {**payload, "iat": int(now.timestamp()), "exp": int((now + timedelta(minutes=10)).timestamp())}
            none_token = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(unsigned_payload)}."
            await run.call("Unsigned token (alg=none)", "GET", "/records/202", 401, none_token)
            tok = await run.login("alice")
            if tok:
                h, _p, s = tok.split(".")
                tampered = f"{h}.{_b64({**unsigned_payload, 'sub': 'bob'})}.{s}"
                await run.call("Tampered payload (sub changed to bob)", "GET", "/records/202", 401, tampered)

        elif name == "expired_token":
            past = datetime.now(timezone.utc) - timedelta(hours=2)
            expired = jwt.encode(
                {"sub": "alice", "role": "user", "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
                 "iat": past, "exp": past + timedelta(minutes=30)},
                settings.jwt_secret, algorithm=settings.jwt_algorithm)
            await run.call("Correctly signed but expired token", "GET", "/records/101", 401, expired)

        elif name == "injection":
            tok = await run.login("alice")
            exp = _expected(400, mandatory=False)
            await run.call("SQL injection in query", "GET", "/records/101?q=' OR 1=1--", exp, tok)
            await run.call("XSS in JSON body", "POST", "/records", exp, tok,
                           json={"title": "<script>alert(document.cookie)</script>", "content": "x"})
            await run.call("Path traversal in query", "GET", "/records?file=../../etc/passwd", exp, tok)

        elif name == "rate_limit":
            tok = await run.login("mallory")
            limit = runtime.rate_limit_requests
            blocked_code = _expected(429, mandatory=False)
            statuses = []
            for _ in range(limit + 5):
                r = await client.get("/records/301", headers={"Authorization": f"Bearer {tok}",
                                                                "User-Agent": "api-fortress-attack-lab"})
                statuses.append(r.status_code)
            limited = sum(1 for s in statuses if s == 429)
            run.steps.append({
                "label": f"Send {limit + 5} requests (limit {limit}/{runtime.rate_limit_window}s)",
                "method": "GET", "path": "/records/301",
                "status": 429 if limited else statuses[-1],
                "expected": [blocked_code],
                "passed": (limited > 0) if blocked_code == 429 else (limited == 0),
                "decision": "blocked" if limited else "allowed",
                "rule": "RATE-001" if limited else None,
                "message": f"{statuses.count(200)} succeeded, {limited} rejected with 429",
            })
    except httpx.HTTPError as exc:
        run.steps.append({"label": "Gateway unreachable", "method": "-", "path": settings.self_url, "status": 0,
                          "expected": [], "passed": False, "decision": None, "rule": None, "message": str(exc)})
    finally:
        if owns_client:
            await client.aclose()

    return {
        "scenario": name,
        **SCENARIOS[name],
        "mode": runtime.mode,
        "passed": all(s["passed"] for s in run.steps),
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        "steps": run.steps,
    }
