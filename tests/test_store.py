"""Tests for the filesystem-backed vulnerability store (osv_service.store)."""

from __future__ import annotations

import json
from pathlib import Path

from osv_service.store import JsonFileStore


def _write_record(root: Path, ecosystem: str, vuln_id: str, record: dict) -> None:
    eco_dir = root / ecosystem
    eco_dir.mkdir(parents=True, exist_ok=True)
    (eco_dir / f"{vuln_id}.json").write_text(json.dumps(record), encoding="utf-8")


def test_load_missing_dir_is_empty() -> None:
    store = JsonFileStore(Path("/nonexistent/osv/store/path"))
    store.load()
    assert store.all_vulns() == []
    assert store.candidate_vulns("pypi", "foo") == []


def test_load_skips_invalid_json(tmp_path: Path) -> None:
    eco_dir = tmp_path / "PyPI"
    eco_dir.mkdir()
    (eco_dir / "bad.json").write_text("{not valid json", encoding="utf-8")
    store = JsonFileStore(tmp_path)
    store.load()
    assert store.all_vulns() == []


def test_load_skips_records_without_id(tmp_path: Path) -> None:
    eco_dir = tmp_path / "PyPI"
    eco_dir.mkdir()
    (eco_dir / "noid.json").write_text(json.dumps({"affected": []}), encoding="utf-8")
    store = JsonFileStore(tmp_path)
    store.load()
    assert store.get("noid") is None


def test_load_indexes_by_package_and_purl(tmp_path: Path) -> None:
    eco_dir = tmp_path / "PyPI"
    eco_dir.mkdir()
    rec_pkg = {"id": "V1", "affected": [{"package": {"name": "foo", "ecosystem": "PyPI"}}]}
    rec_purl = {"id": "V2", "affected": [{"package": {"purl": "pkg:pypi/bar@1.0"}}]}
    (eco_dir / "V1.json").write_text(json.dumps(rec_pkg), encoding="utf-8")
    (eco_dir / "V2.json").write_text(json.dumps(rec_purl), encoding="utf-8")

    store = JsonFileStore(tmp_path)
    store.load()

    assert len(store.all_vulns()) == 2
    assert store.get("V1") is not None
    assert store.get("V2") is not None
    assert len(store.candidate_vulns("pypi", "foo")) == 1
    assert len(store.candidate_vulns("pypi", "bar")) == 1


def test_load_is_case_insensitive_on_ecosystem(tmp_path: Path) -> None:
    _write_record(tmp_path, "PyPI", "V1", {"id": "V1", "affected": [{"package": {"name": "foo", "ecosystem": "PyPI"}}]})
    store = JsonFileStore(tmp_path)
    store.load()
    # Query with a differently-cased ecosystem.
    assert store.candidate_vulns("PYPI", "foo")
    assert store.candidate_vulns("pypi", "foo")


def test_add_persists_and_indexes(tmp_path: Path) -> None:
    store = JsonFileStore(tmp_path)
    record = {"id": "V3", "affected": [{"package": {"name": "baz", "ecosystem": "PyPI"}}]}
    store.add("PyPI", "V3", record)

    # In-memory state.
    assert store.get("V3") is not None
    assert len(store.candidate_vulns("pypi", "baz")) == 1

    # Persisted to disk.
    assert (tmp_path / "PyPI" / "V3.json").exists()

    # A fresh store loading from disk sees it.
    store2 = JsonFileStore(tmp_path)
    store2.load()
    assert store2.get("V3") is not None
    assert len(store2.candidate_vulns("pypi", "baz")) == 1


def test_add_overwrites_existing(tmp_path: Path) -> None:
    store = JsonFileStore(tmp_path)
    store.add("PyPI", "V4", {"id": "V4", "affected": [{"package": {"name": "x", "ecosystem": "PyPI"}}]})
    store.add("PyPI", "V4", {"id": "V4", "affected": [{"package": {"name": "y", "ecosystem": "PyPI"}}]})
    assert len(store.all_vulns()) == 1
    assert len(store.candidate_vulns("pypi", "y")) == 1
    assert len(store.candidate_vulns("pypi", "x")) == 0


def test_candidate_vulns_missing_key(tmp_path: Path) -> None:
    store = JsonFileStore(tmp_path)
    store.load()
    assert store.candidate_vulns("does-not-exist", "nope") == []
