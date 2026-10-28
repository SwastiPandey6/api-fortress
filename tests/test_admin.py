"""Tests for the admin API: session protection, ingestion, policy and attack lab."""
from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "sample_logs"


@pytest.mark.parametrize("path", ["/admin/api/overview", "/admin/api/events", "/admin/api/settings",
                                  "/admin/api/ingest/batches", "/admin/api/simulate"])
def test_admin_routes_require_session(gateway, path):
    assert gateway.get(path).status_code == 401


def test_admin_login_rejects_bad_password(gateway):
    r = gateway.post("/admin/api/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401


def test_admin_login_is_throttled(gateway):
    codes = [gateway.post("/admin/api/login", json={"username": "admin", "password": "nope"}).status_code
             for _ in range(12)]
    assert codes[-1] == 429


def test_session_cookie_is_httponly(gateway):
    r = gateway.post("/admin/api/login", json={"username": "admin", "password": "test-admin-password"})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_upload_wazuh_creates_batch_and_events(admin):
    with open(SAMPLES / "wazuh_alerts.json", "rb") as f:
        r = admin.post("/admin/api/ingest/upload", files={"file": ("alerts.json", f, "application/json")},
                       data={"source": "auto"})
    assert r.status_code == 200, r.text
    batch = r.json()
    assert batch["source"] == "wazuh" and batch["records_parsed"] == batch["records_total"] and batch["alerts"] > 0
    events = admin.get("/admin/api/events", params={"origin": "imported", "batch_id": batch["id"]}).json()
    assert events["total"] == batch["records_parsed"]
    assert all(e["origin"] == "imported" and e["source"] == "wazuh" for e in events["items"])
    detail = admin.get(f"/admin/api/events/{events['items'][0]['id']}").json()
    assert detail["raw"] is not None


def test_imported_alerts_never_counted_as_gateway_blocks(admin):
    with open(SAMPLES / "suricata_eve.json", "rb") as f:
        admin.post("/admin/api/ingest/upload", files={"file": ("eve.json", f)}, data={"source": "suricata"})
    ov = admin.get("/admin/api/overview").json()
    assert ov["gateway"]["blocked"] == 0 and ov["imported"]["total"] > 0


def test_upload_rejects_empty_file(admin):
    r = admin.post("/admin/api/ingest/upload", files={"file": ("e.json", b"   ")}, data={"source": "auto"})
    assert r.status_code == 422


def test_push_ingestion_requires_token(gateway):
    body = (SAMPLES / "modsecurity_audit.json").read_bytes()
    assert gateway.post("/admin/api/ingest/push", content=body).status_code == 401
    r = gateway.post("/admin/api/ingest/push", content=body, headers={"X-Ingest-Token": "test-ingest-token"})
    assert r.status_code == 200 and r.json()["channel"] == "push" and r.json()["source"] == "modsecurity"


def test_mode_change_persists_and_applies(admin, token):
    r = admin.put("/admin/api/settings", json={"mode": "monitor"})
    assert r.json()["policy"]["mode"] == "monitor"
    assert admin.get("/admin/api/settings").json()["policy"]["mode"] == "monitor"
    resp = admin.get("/records/202", headers={"Authorization": f"Bearer {token('alice')}"})
    assert resp.status_code == 200


def test_invalid_mode_rejected(admin):
    assert admin.put("/admin/api/settings", json={"mode": "yolo"}).status_code == 422


def test_overview_and_timeline_shapes(admin, token):
    admin.get("/records/101", headers={"Authorization": f"Bearer {token('alice')}"})
    admin.get("/records/101")
    ov = admin.get("/admin/api/overview").json()
    assert ov["gateway"]["total"] >= 3 and ov["gateway"]["blocked"] >= 1
    tl = admin.get("/admin/api/timeline", params={"range": "60m"}).json()
    assert sum(b["allowed"] + b["blocked"] for b in tl["buckets"]) >= 3


def test_csv_export(admin, token):
    admin.get("/records/101")
    r = admin.get("/admin/api/events/export.csv", params={"origin": "gateway"})
    assert r.status_code == 200 and r.text.startswith("id,created_at")


@pytest.mark.parametrize("scenario", ["legitimate", "bola", "missing_token", "forged_token", "expired_token", "injection"])
def test_attack_lab_scenarios_pass_in_enforce_mode(admin, scenario):
    r = admin.post(f"/admin/api/simulate/{scenario}")
    assert r.status_code == 200
    result = r.json()
    assert result["passed"], result["steps"]


def test_attack_lab_rate_limit(admin):
    admin.put("/admin/api/settings", json={"rate_limit_requests": 5})
    result = admin.post("/admin/api/simulate/rate_limit").json()
    assert result["passed"], result["steps"]


def test_attack_lab_bola_in_monitor_mode_expects_forwarding(admin):
    admin.put("/admin/api/settings", json={"mode": "monitor"})
    result = admin.post("/admin/api/simulate/bola").json()
    assert result["passed"] and all(s["status"] == 200 for s in result["steps"][1:])


def test_clear_events(admin):
    admin.get("/records/101")
    assert admin.delete("/admin/api/events", params={"origin": "gateway"}).json()["deleted"] >= 1


def test_dashboard_served_with_security_headers(gateway):
    r = gateway.get("/dashboard")
    assert r.status_code == 200 and "API Fortress" in r.text
    assert r.headers["x-frame-options"] == "DENY" and "content-security-policy" in r.headers
