"""API-level tests for POST /normalize using FastAPI's TestClient."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_normalize_basic():
    response = client.post(
        "/normalize",
        json={
            "allow": ["10.0.0.0/24", "10.0.0.0/24", "2001:db8::/32"],
            "deny": ["10.0.0.128/25"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ipv4"] == ["10.0.0.0/25"]
    assert data["ipv6"] == ["2001:db8::/32"]
    assert data["stats"]["allow"] == {
        "input": 3, "unique": 2, "duplicates_removed": 1,
        "ipv4": 1, "ipv6": 1,
    }
    assert data["stats"]["deny"] == {
        "input": 1, "unique": 1, "duplicates_removed": 0,
        "ipv4": 1, "ipv6": 0,
    }
    assert data["stats"]["output"] == {"ipv4": 1, "ipv6": 1, "total": 2}


def test_empty_body_defaults_to_empty_lists():
    response = client.post("/normalize", json={})
    assert response.status_code == 200
    assert response.json() == {
        "ipv4": [],
        "ipv6": [],
        "stats": {
            "allow": {"input": 0, "unique": 0, "duplicates_removed": 0,
                      "ipv4": 0, "ipv6": 0},
            "deny": {"input": 0, "unique": 0, "duplicates_removed": 0,
                     "ipv4": 0, "ipv6": 0},
            "output": {"ipv4": 0, "ipv6": 0, "total": 0},
        },
    }


def test_invalid_cidr_returns_422():
    response = client.post(
        "/normalize",
        json={"allow": ["10.0.0.0/24", "bogus"], "deny": []},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(err["loc"][-1] == "allow" for err in detail)


def test_host_bits_return_422():
    response = client.post(
        "/normalize",
        json={"allow": [], "deny": ["10.0.0.1/24"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "deny" for err in response.json()["detail"])


def test_wrong_type_returns_422():
    response = client.post(
        "/normalize",
        json={"allow": [10], "deny": []},
    )
    assert response.status_code == 422


def test_doc_and_openapi_available():
    assert client.get("/docs").status_code == 200
    spec = client.get("/openapi.json").json()
    assert "/normalize" in spec["paths"]
