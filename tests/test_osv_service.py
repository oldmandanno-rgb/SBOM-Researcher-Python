"""Tests for the local OSV.dev mirror (src/osv_service).

Validates API parity with the public OSV.dev contract and proves that
SBOM-Researcher's existing OSVClient works unchanged against the local service.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from osv_service.app import create_app
from osv_service.store import JsonFileStore
from sbom_researcher.osv_client import OSVClient

PAGE_SIZE = 1000


def _make_vuln(vid: str, affected: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": vid,
        "summary": f"Vuln {vid}",
        "details": "test",
        "modified": "2024-01-01T00:00:00Z",
        "published": "2024-01-01T00:00:00Z",
        "affected": affected,
        "schema_version": "1.4.0",
    }


def _pypi(name: str, **kwargs: Any) -> dict[str, Any]:
    pkg = {"name": name, "ecosystem": "PyPI"}
    return {"package": pkg, **kwargs}


@pytest.fixture
def store(tmp_path: Path) -> JsonFileStore:
    root = tmp_path / "data"
    store = JsonFileStore(root)

    store.add(
        "PyPI",
        "OSV-REQ-1",
        _make_vuln(
            "OSV-REQ-1",
            [
                _pypi(
                    "requests",
                    ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.0"}]}],
                    versions=["2.0.0", "2.1.0"],
                )
            ],
        ),
    )
    store.add(
        "PyPI",
        "OSV-REQ-WD",
        _make_vuln(
            "OSV-REQ-WD",
            [_pypi("requests", ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}])],
        ),
    )
    # Mark withdrawn: must never be returned.
    wd = store.get("OSV-REQ-WD")
    assert wd is not None
    wd["withdrawn"] = "2024-06-01T00:00:00Z"

    store.add(
        "PyPI",
        "OSV-FLASK-1",
        _make_vuln(
            "OSV-FLASK-1",
            [_pypi("flask", ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}])],
        ),
    )
    store.add(
        "npm",
        "OSV-LODASH-1",
        _make_vuln(
            "OSV-LODASH-1",
            [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.0.0"}]}],
                }
            ],
        ),
    )
    return store


@pytest.fixture
def client(store: JsonFileStore) -> TestClient:
    return TestClient(create_app(store))


def _purl_query(purl: str) -> dict[str, Any]:
    return {"package": {"purl": purl}}


# --- /v1/query parity -------------------------------------------------------

def test_query_by_purl_version_in_range(client: TestClient) -> None:
    resp = client.post("/v1/query", json=_purl_query("pkg:pypi/requests@2.1.0"))
    assert resp.status_code == 200
    ids = [v["id"] for v in resp.json()["vulns"]]
    assert "OSV-REQ-1" in ids


def test_query_by_purl_version_out_of_range(client: TestClient) -> None:
    resp = client.post("/v1/query", json=_purl_query("pkg:pypi/requests@2.3.0"))
    assert resp.status_code == 200
    assert resp.json()["vulns"] == []


def test_withdrawn_records_excluded(client: TestClient) -> None:
    resp = client.post("/v1/query", json=_purl_query("pkg:pypi/requests@1.0.0"))
    ids = [v["id"] for v in resp.json()["vulns"]]
    assert "OSV-REQ-WD" not in ids


def test_query_by_name_ecosystem(client: TestClient) -> None:
    resp = client.post(
        "/v1/query",
        json={"version": "1.5.0", "package": {"name": "flask", "ecosystem": "PyPI"}},
    )
    assert resp.status_code == 200
    ids = [v["id"] for v in resp.json()["vulns"]]
    assert "OSV-FLASK-1" in ids


def test_query_semver_range(client: TestClient) -> None:
    resp = client.post("/v1/query", json=_purl_query("pkg:npm/lodash@3.10.0"))
    ids = [v["id"] for v in resp.json()["vulns"]]
    assert "OSV-LODASH-1" in ids


def test_query_cargo_mapped_to_crates_io(client: TestClient) -> None:
    store = client.app.state.store
    store.add(
        "crates.io",
        "OSV-SERDE-1",
        _make_vuln(
            "OSV-SERDE-1",
            [
                {
                    "package": {"name": "serde", "ecosystem": "crates.io"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
                }
            ],
        ),
    )
    resp = client.post("/v1/query", json=_purl_query("pkg:cargo/serde@0.9.0"))
    ids = [v["id"] for v in resp.json()["vulns"]]
    assert "OSV-SERDE-1" in ids


def test_query_package_only_returns_all(client: TestClient) -> None:
    resp = client.post("/v1/query", json=_purl_query("pkg:pypi/requests"))
    ids = [v["id"] for v in resp.json()["vulns"]]
    assert "OSV-REQ-1" in ids


def test_query_invalid_both_versions(client: TestClient) -> None:
    resp = client.post(
        "/v1/query",
        json={"version": "1.0", "package": {"purl": "pkg:pypi/requests@2.0"}},
    )
    assert resp.status_code == 400


def test_query_invalid_no_package(client: TestClient) -> None:
    resp = client.post("/v1/query", json={"version": "1.0"})
    assert resp.status_code == 400


# --- pagination --------------------------------------------------------------

def test_query_pagination(client: TestClient) -> None:
    store = client.app.state.store
    for i in range(PAGE_SIZE + 5):
        store.add(
            "PyPI",
            f"OSV-PAGE-{i}",
            _make_vuln(
                f"OSV-PAGE-{i}",
                [_pypi("pagepkg", ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}])],
            ),
        )
    first = client.post("/v1/query", json=_purl_query("pkg:pypi/pagepkg"))
    body = first.json()
    assert len(body["vulns"]) == PAGE_SIZE
    assert body["next_page_token"]

    second = client.post(
        "/v1/query",
        json={**_purl_query("pkg:pypi/pagepkg"), "page_token": body["next_page_token"]},
    )
    assert len(second.json()["vulns"]) == 5
    assert second.json()["next_page_token"] is None


# --- /v1/querybatch ----------------------------------------------------------

def test_querybatch(client: TestClient) -> None:
    resp = client.post(
        "/v1/querybatch",
        json={
            "queries": [
                _purl_query("pkg:pypi/requests@2.1.0"),
                _purl_query("pkg:pypi/flask@1.5.0"),
            ]
        },
    )
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 2
    assert results[0]["vulns"][0]["id"] == "OSV-REQ-1"
    assert "modified" in results[0]["vulns"][0]


# --- /v1/vulns/{id} ----------------------------------------------------------

def test_get_vuln_by_id(client: TestClient) -> None:
    resp = client.get("/v1/vulns/OSV-REQ-1")
    assert resp.status_code == 200
    assert resp.json()["id"] == "OSV-REQ-1"


def test_get_vuln_not_found(client: TestClient) -> None:
    resp = client.get("/v1/vulns/DOES-NOT-EXIST")
    assert resp.status_code == 404


# --- end-to-end: SBOM-Researcher OSVClient against the local service --------

class _TestClientAdapter:
    """Adapts a FastAPI TestClient to the httpx-like interface OSVClient uses."""

    def __init__(self, test_client: TestClient) -> None:
        self._tc = test_client

    def post(self, url: str, json: Any = None) -> Any:  # noqa: A002
        return self._tc.post(url, json=json)

    def close(self) -> None:
        pass


def test_osv_client_against_local_service(store: JsonFileStore) -> None:
    """SBOM-Researcher's OSVClient talks to the mirror unchanged."""
    test_client = TestClient(create_app(store))
    osv = OSVClient()
    osv.client = _TestClientAdapter(test_client)  # type: ignore[assignment]

    # cargo -> crates.io mapping is applied by OSVClient before the request.
    response = osv.query("pkg:cargo/serde@0.9.0")
    assert "vulns" in response

    # A real query that should produce parsed vulnerabilities.
    osv2 = OSVClient()
    osv2.client = _TestClientAdapter(test_client)  # type: ignore[assignment]
    response = osv2.query("pkg:pypi/requests@2.1.0")
    vulns = osv2.parse_vulnerabilities(
        __import__("sbom_researcher.models", fromlist=["Component"]).Component(
            name="requests", version="2.1.0", purl="pkg:pypi/requests@2.1.0"
        ),
        response,
    )
    assert any(v.id == "OSV-REQ-1" for v in vulns)
