import os, tempfile
import pytest

# Use throwaway databases so tests never touch real data.
_tmp = tempfile.mkdtemp()
os.environ["DEMO_DB_URL"] = f"sqlite:///{_tmp}/demo.db"
os.environ["GATEWAY_DB_URL"] = f"sqlite:///{_tmp}/gateway.db"

from fastapi.testclient import TestClient  # noqa: E402
from demo_api.main import app  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("DEMO_VULNERABLE", "true")
    with TestClient(app) as c:
        yield c


def login(client, user, password):
    r = client.post("/login", json={"username": user, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


@pytest.fixture()
def alice(client):
    return login(client, "alice", "alice-pass")


@pytest.fixture()
def bob(client):
    return login(client, "bob", "bob-pass")
