"""HTTP-level tests using FastAPI's TestClient."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_simple_cut_and_counts():
    resp = client.post(
        "/normalize",
        json={
            "allow": ["10.0.0.0/24", "10.0.0.5/24", "10.0.1.0/24"],
            "deny": ["10.0.0.0/25"],
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["ipv4"]["networks"] == ["10.0.0.128/25", "10.0.1.0/24"]
    assert data["ipv6"]["networks"] == []
    assert data["counts"]["ipv4"] == {"input": 3, "unique": 2, "output": 2}
    assert data["counts"]["ipv6"] == {"input": 0, "unique": 0, "output": 0}


def test_recursive_split_through_supernet():
    resp = client.post(
        "/normalize",
        json={"allow": ["10.0.0.0/22"], "deny": ["10.0.0.0/24"]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ipv4"]["networks"] == ["10.0.1.0/24", "10.0.2.0/23"]


def test_only_complete_siblings_merge():
    # Adjacent but non-sibling blocks stay separate.
    resp = client.post(
        "/normalize",
        json={"allow": ["10.0.0.0/25", "10.0.0.192/26"]},
    )
    assert resp.status_code == 200
    assert resp.json()["ipv4"]["networks"] == [
        "10.0.0.0/25",
        "10.0.0.192/26",
    ]


def test_ipv6_cut():
    resp = client.post(
        "/normalize",
        json={"allow": ["2001:db8::/32"], "deny": ["2001:db8::/33"]},
    )
    assert resp.status_code == 200
    assert resp.json()["ipv6"]["networks"] == ["2001:db8:8000::/33"]


def test_empty_body_defaults():
    resp = client.post("/normalize", json={})
    assert resp.status_code == 200
    assert resp.json()["counts"] == {
        "ipv4": {"input": 0, "unique": 0, "output": 0},
        "ipv6": {"input": 0, "unique": 0, "output": 0},
    }


def test_invalid_cidr_allow_returns_422():
    resp = client.post("/normalize", json={"allow": ["not-a-cidr"]})
    assert resp.status_code == 422
    detail = resp.json()["detail"][0]
    assert detail["type"] == "invalid_cidr"
    assert detail["index"] == 0
    assert detail["value"] == "not-a-cidr"


def test_invalid_prefix_length_returns_422():
    resp = client.post("/normalize", json={"allow": ["10.0.0.0/33"]})
    assert resp.status_code == 422


def test_invalid_cidr_deny_keeps_index():
    resp = client.post(
        "/normalize", json={"allow": ["10.0.0.0/8"], "deny": ["999.1.1.1/32"]}
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"][0]
    assert detail["index"] == 0
    assert detail["value"] == "999.1.1.1/32"


def test_malformed_body_returns_422():
    resp = client.post("/normalize", json={"allow": "not-a-list"})
    assert resp.status_code == 422
