"""Shared fixtures.

The gateway and demo API run in-process: the gateway's backend HTTP client is
wired to the demo API through httpx.ASGITransport, so the full request path
(client -> gateway -> backend) is exercised without opening network ports.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_TMP = Path(tempfile.mkdtemp(prefix="fortress-tests-"))
os.environ.update(
    {
        "APP_ENV": "test",
        "DATABASE_URL": f"sqlite:///{(_TMP / 'fortress.db').as_posix()}",
        "DEMO_DB_PATH": str(_TMP / "demo.db"),
        "GATEWAY_MODE": "enforce",
        "RATE_LIMIT_REQUESTS": "30",
        "RATE_LIMIT_WINDOW_SECONDS": "60",
        "ADMIN_USERNAME": "admin",
        "ADMIN_PASSWORD": "test-admin-password",
        "INGEST_TOKEN": "test-ingest-token",
        "BACKEND_URL": "http://backend",
        "GATEWAY_SELF_URL": "http://gateway",
    }
)

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import proxy, simulator  # noqa: E402
from app.events import clear_events  # noqa: E402
from app.main import app as gateway_app  # noqa: E402
from app.runtime import runtime  # noqa: E402
from app.security.authorization import ownership  # noqa: E402
from app.security.rate_limit import admin_login_limiter, limiter  # noqa: E402
from demo_api import db as demo_db  # noqa: E402
from demo_api.main import app as demo_app  # noqa: E402

PASSWORDS = {"alice": "Alice@123", "bob": "Bob@123", "mallory": "Mallory@123", "admin": "Admin@123"}


@pytest.fixture()
def demo_client():
    demo_db.init_db(reset=True)
    with TestClient(demo_app) as c:
        yield c


@pytest.fixture()
def gateway():
    demo_db.init_db(reset=True)
    backend = httpx.AsyncClient(transport=httpx.ASGITransport(app=demo_app), base_url="http://backend")
    proxy.set_backend_client(backend)
    with TestClient(gateway_app) as client:
        simulator.set_client(httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway_app), base_url="http://gateway"))
        runtime.update(mode="enforce", rate_limit_requests=30, rate_limit_window=60)
        limiter.reset()
        admin_login_limiter.reset()
        ownership.clear()
        clear_events(None)
        yield client
    simulator.set_client(None)
    proxy.set_backend_client(None)


@pytest.fixture()
def token(gateway):
    def _login(user: str) -> str:
        r = gateway.post("/auth/login", json={"username": user, "password": PASSWORDS[user]})
        assert r.status_code == 200, r.text
        return r.json()["access_token"]

    return _login


@pytest.fixture()
def admin(gateway):
    r = gateway.post("/admin/api/login", json={"username": "admin", "password": "test-admin-password"})
    assert r.status_code == 200, r.text
    return gateway


def auth(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}
