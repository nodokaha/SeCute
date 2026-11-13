"""Tracker API tests: the optional write token, value validation
surfacing as 422, and reads staying open."""
import pytest
from fastapi.testclient import TestClient

from app import db, main


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setattr(main, "API_TOKEN", "test-token")
    with TestClient(main.app) as c:
        yield c


def test_mutations_require_the_token(client):
    r = client.post("/api/assets", json={"name": "x"})
    assert r.status_code == 401
    r = client.post("/api/assets", json={"name": "x"},
                    headers={"X-API-Token": "wrong"})
    assert r.status_code == 401
    r = client.post("/api/assets", json={"name": "x"},
                    headers={"X-API-Token": "test-token"})
    assert r.status_code == 200


def test_reads_stay_open_without_a_token(client):
    assert client.get("/api/items").status_code == 200
    assert client.get("/api/assets").status_code == 200
    assert client.get("/api/ingest/runs").status_code == 200
    assert client.get("/health").status_code == 200


def test_invalid_item_values_are_422_not_500(client, tmp_path):
    r = client.post("/api/assets", json={"name": "x"},
                    headers={"X-API-Token": "test-token"})
    asset_id = r.json()["id"]
    conn = db.connect(str(tmp_path / "api.db"))
    db.upsert_vuln(conn, "CVE-2026-9999", "osv", title="t")
    item = db.find_or_create_item(conn, "CVE-2026-9999", asset_id,
                                  title="t")
    conn.commit()
    conn.close()
    r = client.patch(f"/api/items/{item['id']}",
                     json={"status": "bogus"},
                     headers={"X-API-Token": "test-token"})
    assert r.status_code == 422
    r = client.patch(f"/api/items/{item['id']}",
                     json={"status": "patched"},
                     headers={"X-API-Token": "test-token"})
    assert r.status_code == 200
    assert r.json()["status"] == "patched"
