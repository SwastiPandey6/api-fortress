"""Tests for the protected demo API on its own."""
from demo_api import settings

SECRET = {"X-Gateway-Secret": settings.GATEWAY_SHARED_SECRET}


def _login(c, user="alice", pw="Alice@123"):
    r = c.post("/auth/login", json={"username": user, "password": pw}, headers=SECRET)
    assert r.status_code == 200
    return r.json()["access_token"]


def test_health_is_public(demo_client):
    assert demo_client.get("/health").json()["status"] == "ok"


def test_direct_access_without_gateway_secret_is_refused(demo_client):
    r = demo_client.post("/auth/login", json={"username": "alice", "password": "Alice@123"})
    assert r.status_code == 403
    assert "gateway" in r.json()["detail"].lower()


def test_login_success_and_failure(demo_client):
    assert _login(demo_client)
    r = demo_client.post("/auth/login", json={"username": "alice", "password": "wrong"}, headers=SECRET)
    assert r.status_code == 401


def test_list_records_returns_only_own(demo_client):
    tok = _login(demo_client)
    r = demo_client.get("/records", headers={**SECRET, "Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert {rec["owner"] for rec in r.json()["items"]} == {"alice"}


def test_backend_alone_is_vulnerable_to_bola(demo_client):
    """Documents WHY the gateway is needed: the backend has no ownership check."""
    tok = _login(demo_client)
    r = demo_client.get("/records/202", headers={**SECRET, "Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and r.json()["owner"] == "bob"


def test_owner_lookup_requires_secret(demo_client):
    assert demo_client.get("/internal/records/101/owner").status_code == 403
    r = demo_client.get("/internal/records/101/owner", headers=SECRET)
    assert r.json()["owner"] == "alice"
