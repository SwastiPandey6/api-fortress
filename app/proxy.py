"""Reverse proxy: forwards permitted requests to the protected API."""
from __future__ import annotations

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import settings

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
# Headers clients must never be able to inject towards the backend
SPOOFABLE = {"x-gateway-secret", "x-authenticated-user", "x-authenticated-role", "x-request-id"}

_client: httpx.AsyncClient | None = None


def set_backend_client(client: httpx.AsyncClient | None) -> None:
    """Install the HTTP client used for the backend (overridable in tests)."""
    global _client
    _client = client


def get_backend_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=settings.backend_url,
            timeout=httpx.Timeout(settings.backend_timeout),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=False,
        )
    return _client


async def close_backend_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def _forward_headers(request: Request, client_ip: str, request_id: str, claims: dict | None) -> dict[str, str]:
    headers = {
        k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP and k.lower() not in SPOOFABLE
    }
    prior = request.headers.get("x-forwarded-for")
    headers["X-Forwarded-For"] = f"{prior}, {client_ip}" if prior and settings.trust_proxy_headers else client_ip
    headers["X-Forwarded-Proto"] = request.url.scheme
    headers["X-Request-ID"] = request_id
    headers["X-Gateway-Secret"] = settings.gateway_shared_secret
    if claims:
        headers["X-Authenticated-User"] = str(claims.get("sub", ""))
        headers["X-Authenticated-Role"] = str(claims.get("role", "user"))
    return headers


async def forward(
    request: Request, body: bytes, client_ip: str, request_id: str, claims: dict | None
) -> tuple[Response, bool]:
    """Forward the request. Returns (response, upstream_reached)."""
    client = get_backend_client()
    raw_path = request.scope.get("raw_path", request.url.path.encode()).decode("latin-1")
    query = request.url.query
    url = raw_path + (f"?{query}" if query else "")
    try:
        upstream = await client.request(
            request.method,
            url,
            content=body,
            headers=_forward_headers(request, client_ip, request_id, claims),
        )
    except httpx.TimeoutException:
        return JSONResponse(
            {"error": "upstream_timeout", "message": "The protected API did not respond in time", "request_id": request_id},
            status_code=504,
        ), False
    except httpx.HTTPError:
        return JSONResponse(
            {"error": "upstream_unavailable", "message": "The protected API is unreachable", "request_id": request_id},
            status_code=502,
        ), False

    resp_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP and k.lower() != "content-encoding"}
    resp_headers["X-Request-ID"] = request_id
    return Response(content=upstream.content, status_code=upstream.status_code, headers=resp_headers), True
