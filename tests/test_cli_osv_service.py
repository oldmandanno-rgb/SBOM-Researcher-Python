"""Tests for the OSV mirror CLI (osv_service.cli)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import uvicorn
from click.testing import CliRunner

from osv_service import cli
from osv_service.cli import main


def test_serve_loads_store_and_starts_server(monkeypatch: MagicMock, tmp_path: Path) -> None:
    captured: dict = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, host, port: captured.update(app=app, host=host, port=port))

    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--data-dir", str(tmp_path), "--host", "127.0.0.1", "--port", "9"])

    assert result.exit_code == 0
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 9
    assert captured["app"] is not None


def test_download_sync_disabled_is_noop(monkeypatch: MagicMock, tmp_path: Path) -> None:
    called = {"n": 0}
    monkeypatch.setenv("OSV_SYNC_ENABLED", "0")
    monkeypatch.setattr(cli, "sync_once", lambda *a, **k: called.__setitem__("n", called["n"] + 1) or 0)

    runner = CliRunner()
    result = runner.invoke(
        main, ["download", "--data-dir", str(tmp_path), "--outbox", str(tmp_path / "out")]
    )

    assert result.exit_code == 0
    assert "Sync disabled" in result.output
    assert called["n"] == 0


def test_download_single_pass_runs_sync(monkeypatch: MagicMock, tmp_path: Path) -> None:
    monkeypatch.setenv("OSV_SYNC_ENABLED", "1")
    monkeypatch.setattr(cli, "sync_once", lambda *a, **k: 5)

    runner = CliRunner()
    result = runner.invoke(
        main, ["download", "--data-dir", str(tmp_path), "--outbox", str(tmp_path / "out")]
    )

    assert result.exit_code == 0
    assert "Synced 5 new record(s)" in result.output


def test_bundle_nothing_pending(monkeypatch: MagicMock, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "create_bundle", lambda *a, **k: None)

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["bundle", "--data-dir", str(tmp_path), "--outbox", str(tmp_path / "o"), "--transport", str(tmp_path / "t")],
    )

    assert result.exit_code == 0
    assert "Nothing pending to bundle" in result.output


def test_bundle_created(monkeypatch: MagicMock, tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle_2024"
    monkeypatch.setattr(cli, "create_bundle", lambda *a, **k: bundle_path)

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["bundle", "--data-dir", str(tmp_path), "--outbox", str(tmp_path / "o"), "--transport", str(tmp_path / "t")],
    )

    assert result.exit_code == 0
    assert f"Bundle created: {bundle_path}" in result.output


def test_import_bundle(monkeypatch: MagicMock, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "import_bundle", lambda *a, **k: 3)

    runner = CliRunner()
    result = runner.invoke(
        main, ["import-bundle", "--data-dir", str(tmp_path), "--path", str(tmp_path / "bundle_x")]
    )

    assert result.exit_code == 0
    assert "Imported 3 record(s)" in result.output
