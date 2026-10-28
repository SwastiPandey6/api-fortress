"""End-to-end tests of the gateway security pipeline (client -> gateway -> demo API)."""
import base64
import json
from datetime import datetime, timedelta, timezone

import jwt

from app.config import settings
from app.events import query_events
from app.runtime import runtime
from tests.conftest import auth


def last_event():
    _, rows = query_events({"origin": "gateway"}, limit=1)
    return rows[0]


# ---- legitimate traffic -------------------------------------------------------
def test_login_passes_through_gateway(gateway):
    r = gateway.post("/auth/login", json={"username": "alice", "password": "Alice@123"})
    assert r.status_code == 200
    assert r.headers["x-fortress-decision"] == "allowed"


def test_owner_can_read_own_record(gateway, token):
    r = gateway.get("/records/101", headers=auth(token("alice")))
    assert r.status_code == 200 and r.json()["owner"] == "alice"
    ev = last_event()
    assert ev["decision"] == "allowed" and ev["username"] == "alice" and ev["status_code"] == 200


def test_admin_role_may_read_any_record(gateway, token):
    assert gateway.get("/records/202", headers=auth(token("admin"))).status_code == 200


def test_unknown_record_returns_backend_404(gateway, token):
    assert gateway.get("/records/99999", headers=auth(token("alice"))).status_code == 404


# ---- authentication -------------------------------------------------------------
def test_missing_token_rejected(gateway):
    r = gateway.get("/records/101")
    assert r.status_code == 401 and r.json()["rule"] == "AUTH-001"
    assert last_event()["decision"] == "blocked"


def test_forged_signature_rejected(gateway):
    now = datetime.now(timezone.utc)
    forged = jwt.encode({"sub": "alice", "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
                         "iat": now, "exp": now + timedelta(minutes=5)}, "x" * 40, algorithm="HS256")
    r = gateway.get("/records/101", headers=auth(forged))
    assert r.status_code == 401 and r.json()["rule"] == "AUTH-002"


def test_alg_none_rejected(gateway):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    exp = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())
    tok = f"{enc({'alg': 'none', 'typ': 'JWT'})}.{enc({'sub': 'alice', 'exp': exp, 'iat': exp - 60})}."
    r = gateway.get("/records/101", headers=auth(tok))
    assert r.status_code == 401 and "algorithm" in r.json()["message"].lower()


def test_expired_token_rejected(gateway):
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    tok = jwt.encode({"sub": "alice", "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
                      "iat": past, "exp": past + timedelta(minutes=5)}, settings.jwt_secret, algorithm="HS256")
    r = gateway.get("/records/101", headers=auth(tok))
    assert r.status_code == 401 and r.json()["rule"] == "AUTH-003"


def test_wrong_audience_rejected(gateway):
    now = datetime.now(timezone.utc)
    tok = jwt.encode({"sub": "alice", "iss": settings.jwt_issuer, "aud": "other-api",
                      "iat": now, "exp": now + timedelta(minutes=5)}, settings.jwt_secret, algorithm="HS256")
    assert gateway.get("/records/101", headers=auth(tok)).json()["rule"] == "AUTH-004"


def test_auth_failures_block_even_in_monitor_mode(gateway):
    runtime.update(mode="monitor")
    assert gateway.get("/records/101").status_code == 401


def test_spoofed_identity_headers_are_stripped(gateway, token):
    r = gateway.get("/records/101", headers={**auth(token("alice")), "X-Authenticated-User": "admin",
                                              "X-Gateway-Secret": "guess"})
    assert r.status_code == 200


# ---- authorization (BOLA) -----------------------------------------------------------
def test_bola_blocked_in_enforce_mode(gateway, token):
    r = gateway.get("/records/202", headers=auth(token("alice")))
    assert r.status_code == 403 and r.json()["rule"] == "AUTHZ-001"
    ev = last_event()
    assert ev["decision"] == "blocked" and ev["classification"] == "broken_object_level_authorization"


def test_bola_write_blocked(gateway, token):
    r = gateway.put("/records/202", headers=auth(token("alice")), json={"title": "x", "content": "y"})
    assert r.status_code == 403


def test_bola_flagged_but_forwarded_in_monitor_mode(gateway, token):
    runtime.update(mode="monitor")
    r = gateway.get("/records/202", headers=auth(token("alice")))
    assert r.status_code == 200 and r.headers["x-fortress-decision"] == "flagged"
    assert last_event()["rule_id"] == "AUTHZ-001"


def test_learning_mode_records_profiles(gateway, token, admin):
    runtime.update(mode="learning")
    tok = token("alice")
    gateway.get("/records/101", headers=auth(tok))
    gateway.get("/records/102", headers=auth(tok))
    r = gateway.get("/records/202", headers=auth(tok))
    assert r.headers["x-fortress-decision"] == "observed"
    profiles = admin.get("/admin/api/profiles").json()["items"]
    rec = next(p for p in profiles if p["path_template"] == "/records/{id}" and p["method"] == "GET")
    assert rec["hits"] == 3


# ---- rate limiting -------------------------------------------------------------------
def test_rate_limit_returns_429(gateway, token):
    runtime.update(rate_limit_requests=5, rate_limit_window=60)
    tok = token("mallory")
    codes = [gateway.get("/records/301", headers=auth(tok)).status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429] * 3
    r = gateway.get("/records/301", headers=auth(tok))
    assert "retry-after" in r.headers and r.json()["rule"] == "RATE-001"


# ---- input inspection -----------------------------------------------------------
def test_sql_injection_in_query_blocked(gateway, token):
    r = gateway.get("/records/101", params={"q": "' OR 1=1--"}, headers=auth(token("alice")))
    assert r.status_code == 400 and r.json()["rule"] == "REQ-001"


def test_xss_in_body_blocked(gateway, token):
    r = gateway.post("/records", headers=auth(token("alice")), json={"title": "<script>alert(1)</script>", "content": "x"})
    assert r.status_code == 400


def test_clean_body_allowed(gateway, token):
    r = gateway.post("/records", headers=auth(token("alice")), json={"title": "Groceries", "content": "Milk, rice, dal"})
    assert r.status_code == 201 and r.json()["owner"] == "alice"


def test_oversized_payload_rejected(gateway, token):
    body = "a" * (settings.max_body_bytes + 10)
    r = gateway.post("/records", headers={**auth(token("alice")), "Content-Type": "text/plain"}, content=body)
    assert r.status_code == 413


# ---- infrastructure -------------------------------------------------------------
def test_gateway_health(gateway):
    assert gateway.get("/gateway/health").json()["status"] == "ok"


def test_backend_down_returns_502(gateway, token):
    import httpx

    from app import proxy

    tok = token("alice")
    proxy.set_backend_client(httpx.AsyncClient(base_url="http://127.0.0.1:1"))
    r = gateway.get("/users/me", headers=auth(tok))
    assert r.status_code == 502
    assert last_event()["decision"] == "error"
