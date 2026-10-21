import time
import jwt
from demo_api.security import JWT_ALG, JWT_SECRET


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_login_ok_and_bad_password(client):
    assert client.post("/login", json={"username": "alice", "password": "alice-pass"}).status_code == 200
    assert client.post("/login", json={"username": "alice", "password": "nope"}).status_code == 401
    assert client.post("/login", json={"username": "ghost", "password": "x"}).status_code == 401


def test_requires_token(client):
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_expired_token_rejected(client):
    old = jwt.encode({"sub": "1", "exp": int(time.time()) - 10}, JWT_SECRET, algorithm=JWT_ALG)
    assert client.get("/me", headers={"Authorization": f"Bearer {old}"}).status_code == 401


def test_each_user_sees_only_own_list(client, alice, bob):
    a = client.get("/records", headers=alice).json()
    b = client.get("/records", headers=bob).json()
    assert {r["title"].split(" - ")[0] for r in a} == {"Alice"}
    assert {r["title"].split(" - ")[0] for r in b} == {"Bob"}
    assert not {r["id"] for r in a} & {r["id"] for r in b}


def test_owner_can_read_own_record(client, alice):
    rid = client.get("/records", headers=alice).json()[0]["id"]
    r = client.get(f"/records/{rid}", headers=alice)
    assert r.status_code == 200 and "Alice" in r.json()["content"]


def test_vulnerable_mode_allows_cross_user_read(client, alice, bob):
    """The deliberate BOLA flaw the gateway must later block."""
    bob_id = client.get("/records", headers=bob).json()[0]["id"]
    r = client.get(f"/records/{bob_id}", headers=alice)
    assert r.status_code == 200 and "Bob" in r.json()["content"]


def test_safe_mode_blocks_cross_user_read(client, alice, bob, monkeypatch):
    bob_id = client.get("/records", headers=bob).json()[0]["id"]
    monkeypatch.setenv("DEMO_VULNERABLE", "false")
    assert client.get(f"/records/{bob_id}", headers=alice).status_code == 403


def test_vulnerable_mode_allows_role_escalation(client, bob):
    r = client.patch("/me", headers=bob, json={"role": "admin"})
    assert r.json()["role"] == "admin"
    client.patch("/me", headers=bob, json={"role": "user"})  # restore


def test_safe_mode_ignores_role_field(client, bob, monkeypatch):
    monkeypatch.setenv("DEMO_VULNERABLE", "false")
    assert client.patch("/me", headers=bob, json={"role": "admin"}).json()["role"] == "user"
