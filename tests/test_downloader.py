"""Tests for ingestion (GCS sync) and DMZ -> intranet bundle transfer.

GCS is mocked so the test runs offline; the JSON + CSV protocol is exercised
exactly as the real service would.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from osv_service.downloader import create_bundle, import_bundle, sync_once
from osv_service.store import JsonFileStore

RECORD = {
    "id": "PYSEC-2024-1",
    "summary": "test",
    "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"}}],
}


class _FakeResponse:
    def __init__(self, *, text: str | None = None, json_data: Any = None, status_code: int = 200) -> None:
        self._text = text
        self._json = json_data
        self.status_code = status_code

    @property
    def text(self) -> str:
        assert self._text is not None
        return self._text

    def json(self) -> Any:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise AssertionError(f"status {self.status_code}")


class _FakeGCS:
    """Stand-in for httpx.Client speaking the OSV GCS layout."""

    CSV = "2024-08-15T00:05:00Z,PyPI/PYSEC-2024-1\n2024-08-14T00:00:00Z,PyPI/PYSEC-2024-2\n"

    def __init__(self) -> None:
        self.requests: list[str] = []

    def get(self, url: str) -> _FakeResponse:
        self.requests.append(url)
        if url.endswith("modified_id.csv"):
            return _FakeResponse(text=self.CSV)
        # .../<ECOSYSTEM>/<ID>.json
        tail = url.split("https://storage.googleapis.com/osv-vulnerabilities/", 1)[1]
        eco, vid = tail[:-5].split("/", 1)
        rec = dict(RECORD, id=vid)
        return _FakeResponse(json_data=rec)


def test_sync_then_bundle_then_import(tmp_path: Path) -> None:
    dmz_data = tmp_path / "dmz_data"
    outbox = tmp_path / "outbox"
    transport = tmp_path / "transport"
    intra_data = tmp_path / "intra_data"
    last_seen = outbox / "last_seen.txt"

    dmz = JsonFileStore(dmz_data)
    dmz.load()
    gcs = _FakeGCS()

    added = sync_once(dmz, outbox, last_seen, gcs)  # type: ignore[arg-type]
    assert added == 2
    assert dmz.get("PYSEC-2024-1") is not None
    assert (outbox / "pending.csv").exists()

    bundle = create_bundle(dmz_data, outbox, transport)
    assert bundle is not None
    assert (bundle / "manifest.csv").exists()
    assert (bundle / "PyPI" / "PYSEC-2024-1.json").exists()
    # pending consumed into archive
    assert not (outbox / "pending.csv").exists()

    intra = JsonFileStore(intra_data)
    intra.load()
    imported = import_bundle(intra, bundle)
    assert imported == 2
    assert intra.get("PYSEC-2024-1") is not None
    assert intra.get("PYSEC-2024-2") is not None


def test_incremental_sync_stops_at_last_seen(tmp_path: Path) -> None:
    dmz_data = tmp_path / "dmz_data"
    outbox = tmp_path / "outbox"
    last_seen = outbox / "last_seen.txt"

    dmz = JsonFileStore(dmz_data)
    dmz.load()
    gcs = _FakeGCS()
    sync_once(dmz, outbox, last_seen, gcs)  # type: ignore[arg-type]

    # Second sync: nothing new (all CSV rows <= last_seen).
    added = sync_once(dmz, outbox, last_seen, gcs)  # type: ignore[arg-type]
    assert added == 0
