"""Tests for the SBOM-Researcher CLI (sbom_researcher.cli)."""

from __future__ import annotations

from pathlib import Path
from typing import Self
from unittest.mock import MagicMock

import httpx
from click.testing import CliRunner

from sbom_researcher import cli
from sbom_researcher.cli import main
from sbom_researcher.models import (
    Component,
    ComponentLocation,
    LicenseAction,
    LicenseInfo,
    Vulnerability,
)


class FakeParser:
    def __init__(self, components: list[Component], locations: list, licenses: list) -> None:
        self._components = components
        self._locations = locations
        self._licenses = licenses

    def parse(self, sbom_file: Path):
        return self._components, self._locations, self._licenses

    def convert_to_version(self, v: str) -> str:
        return v


class FakeOSV:
    def __init__(self, vulnerabilities: list[Vulnerability] | None = None, raise_on_query: bool = False) -> None:
        self._vulnerabilities = vulnerabilities or []
        self._raise_on_query = raise_on_query

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def query(self, purl: str):
        if self._raise_on_query:
            raise httpx.ConnectError("boom")
        return {"vulns": []}

    def parse_vulnerabilities(self, comp: Component, response: dict, min_score: float):
        return self._vulnerabilities


def test_cli_basic_run_generates_reports(tmp_path: Path, monkeypatch: MagicMock) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")
    out = tmp_path / "out"

    comp = Component(name="foo", version="1.0", purl="pkg:pypi/foo@1.0", license="MIT")
    loc = ComponentLocation(component="foo", version="1.0", file="sbom.json")
    lic = LicenseInfo(name="MIT", action=LicenseAction.LOW)
    monkeypatch.setattr(cli, "SBOMParser", lambda: FakeParser([comp], [loc], [lic]))
    monkeypatch.setattr(cli, "OSVClient", lambda: FakeOSV())

    runner = CliRunner()
    result = runner.invoke(
        main, ["-s", str(sbom), "-o", str(out), "-p", "proj", "--print-licenses"]
    )

    assert result.exit_code == 0, result.output
    assert "Done!" in result.output
    assert (out / "proj_vulns.json").exists()
    assert (out / "proj_locs.json").exists()
    assert (out / "proj_license.json").exists()


def test_cli_sets_recommendation_from_fixed_version(tmp_path: Path, monkeypatch: MagicMock) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")
    out = tmp_path / "out"

    comp = Component(name="foo", version="1.0", purl="pkg:pypi/foo@1.0", license="MIT")
    vuln = Vulnerability(id="OSV-1", source="OSV", fixed_version="1.1")
    loc = ComponentLocation(component="foo", version="1.0", file="sbom.json")
    lic = LicenseInfo(name="MIT", action=LicenseAction.LOW)
    monkeypatch.setattr(cli, "SBOMParser", lambda: FakeParser([comp], [loc], [lic]))
    monkeypatch.setattr(cli, "OSVClient", lambda: FakeOSV(vulnerabilities=[vuln]))

    runner = CliRunner()
    result = runner.invoke(main, ["-s", str(sbom), "-o", str(out), "-p", "proj"])

    assert result.exit_code == 0, result.output
    # Recommendation path (max fixed_version via version_key) executed without error.
    assert (out / "proj_vulns.json").exists()


def test_cli_handles_osv_query_error(tmp_path: Path, monkeypatch: MagicMock) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")
    out = tmp_path / "out"

    comp = Component(name="foo", version="1.0", purl="pkg:pypi/foo@1.0", license="MIT")
    loc = ComponentLocation(component="foo", version="1.0", file="sbom.json")
    lic = LicenseInfo(name="MIT", action=LicenseAction.LOW)
    monkeypatch.setattr(cli, "SBOMParser", lambda: FakeParser([comp], [loc], [lic]))
    monkeypatch.setattr(cli, "OSVClient", lambda: FakeOSV(raise_on_query=True))

    runner = CliRunner()
    result = runner.invoke(main, ["-s", str(sbom), "-o", str(out), "-p", "proj"])

    # Query failure is caught and reported; the run still completes.
    assert result.exit_code == 0, result.output
    assert "Error querying" in result.output
    assert (out / "proj_vulns.json").exists()


def test_cli_directory_mode_parses_each_file(tmp_path: Path, monkeypatch: MagicMock) -> None:
    sbom_dir = tmp_path / "sboms"
    sbom_dir.mkdir()
    (sbom_dir / "a.json").write_text("{}", encoding="utf-8")
    (sbom_dir / "b.json").write_text("{}", encoding="utf-8")
    out = tmp_path / "out"

    # Each file "parses" to one component.
    comp = Component(name="foo", version="1.0", purl="pkg:pypi/foo@1.0", license="MIT")
    loc = ComponentLocation(component="foo", version="1.0", file="a.json")
    lic = LicenseInfo(name="MIT", action=LicenseAction.LOW)
    monkeypatch.setattr(cli, "SBOMParser", lambda: FakeParser([comp], [loc], [lic]))
    monkeypatch.setattr(cli, "OSVClient", lambda: FakeOSV())

    runner = CliRunner()
    result = runner.invoke(main, ["-s", str(sbom_dir), "-o", str(out), "-p", "proj"])

    assert result.exit_code == 0, result.output
    assert "Found 2 SBOM file(s)" in result.output
