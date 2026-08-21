"""Real-data smoke test for the OSV mirror.

Intent: prove the full pipeline (GCS ingestion -> store -> matcher -> API)
works against *real* OSV data, using the absolute minimum amount of network
traffic so it stays suitable for unit testing.

It discovers ONE currently-valid vulnerability id via the live api.osv.dev,
downloads that single record's JSON from the GCS export, ingests it into a
local store, and asserts:

* the local service returns it for the same package query, and
* the local result set is a subset of what the live API returns (parity).

Network access is required; the test skips cleanly when offline so the rest of
the suite stays hermetic. Run explicitly with ``pytest -m smoke``.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from osv_service.app import create_app
from osv_service.downloader import download_record
from osv_service.store import JsonFileStore

LIVE_API = "https://api.osv.dev/v1/query"
PROBE = {"package": {"name": "mruby", "ecosystem": "OSS-Fuzz"}}

pytestmark = pytest.mark.smoke


def _live_query() -> list[dict]:
    try:
        resp = httpx.post(LIVE_API, json=PROBE, timeout=15.0)
        resp.raise_for_status()
        return resp.json().get("vulns", [])
    except httpx.HTTPError:
        pytest.skip("no network access to api.osv.dev")


def test_realdata_ingestion_and_parity(tmp_path) -> None:
    live_vulns = _live_query()
    if not live_vulns:
        pytest.skip("live API returned no vulnerabilities for probe package")

    vid = live_vulns[0]["id"]
    ecosystems = []
    for affected in live_vulns[0].get("affected", []):
        eco = affected.get("package", {}).get("ecosystem")
        if eco and eco not in ecosystems:
            ecosystems.append(eco)

    rec = None
    chosen_eco = None
    with httpx.Client(timeout=15.0) as client:
        for eco in ecosystems:
            rec = download_record(client, eco, vid)
            if rec is not None:
                chosen_eco = eco
                break

    assert rec is not None, f"could not fetch {vid} from GCS export"
    assert rec.get("id") == vid

    store = JsonFileStore(tmp_path / "data")
    store.add(chosen_eco, vid, rec)
    local = TestClient(create_app(store))

    local_resp = local.post("/v1/query", json=PROBE).json()
    local_ids = {v["id"] for v in local_resp["vulns"]}
    assert vid in local_ids

    # Parity: everything our local mirror returns must also be returned by the
    # real API for the same query (we only hold one record, so a subset check).
    live_ids = {v["id"] for v in live_vulns}
    assert local_ids <= live_ids
