"""Tests for report generation (sbom_researcher.reporter)."""

from __future__ import annotations

import json
from pathlib import Path

from sbom_researcher.models import (
    Component,
    ComponentLocation,
    CVSSBreakdown,
    LicenseAction,
    LicenseInfo,
    Report,
    Vulnerability,
)
from sbom_researcher.reporter import Reporter


def _make_report() -> Report:
    cvss = CVSSBreakdown(
        vector="CVSS:3.1/AV:N/AC:L",
        version="3.1",
        base_score=9.8,
        severity="CRITICAL",
        attack_vector="NETWORK",
        score_url="https://example.com/score",
    )
    vuln = Vulnerability(
        id="OSV-1",
        source="OSV",
        summary="bad thing",
        details="it is bad",
        fixed_version="1.1",
        cvss=cvss,
        score=9.8,
        severity="CRITICAL",
    )
    vulnerable = Component(
        name="foo",
        version="1.0",
        purl="pkg:pypi/foo@1.0",
        license="MIT",
        vulnerabilities=[vuln],
        recommendation="1.1",
    )
    clean = Component(name="bar", version="2.0", purl="pkg:pypi/bar@2.0", license="Apache-2.0")
    loc = ComponentLocation(component="foo", version="1.0", file="sbom.json")
    license_info = LicenseInfo(name="MIT", action=LicenseAction.LOW)
    return Report(
        project_name="proj",
        components=[vulnerable, clean],
        locations=[loc],
        licenses=[license_info],
    )


def test_generate_creates_expected_files(tmp_path: Path) -> None:
    reporter = Reporter(tmp_path, "proj")
    reporter.generate(_make_report(), list_all=True, print_licenses=True)

    assert (tmp_path / "proj_report.txt").exists()
    assert (tmp_path / "proj_vulns.json").exists()
    assert (tmp_path / "proj_locs.json").exists()
    assert (tmp_path / "proj_license.json").exists()


def test_text_report_includes_vuln_details(tmp_path: Path) -> None:
    reporter = Reporter(tmp_path, "proj")
    reporter.generate(_make_report(), list_all=True, print_licenses=True)

    text = (tmp_path / "proj_report.txt").read_text(encoding="utf-8")
    assert "foo 1.0" in text
    assert "OSV-1" in text
    assert "CRITICAL" in text
    assert "bad thing" in text
    assert "All components evaluated" in text
    assert "MIT" in text  # license section printed


def test_text_report_respects_list_all_off(tmp_path: Path) -> None:
    reporter = Reporter(tmp_path, "proj")
    reporter.generate(_make_report(), list_all=False, print_licenses=False)

    text = (tmp_path / "proj_report.txt").read_text(encoding="utf-8")
    assert "All components evaluated" not in text
    # License file only written when print_licenses is True.
    assert not (tmp_path / "proj_license.json").exists()


def test_vuln_json_shape(tmp_path: Path) -> None:
    reporter = Reporter(tmp_path, "proj")
    reporter.generate(_make_report())

    data = json.loads((tmp_path / "proj_vulns.json").read_text(encoding="utf-8"))
    assert len(data) == 1
    comp = data[0]
    assert comp["name"] == "foo"
    assert comp["recommendation"] == "1.1"
    assert comp["vulnerabilities"][0]["id"] == "OSV-1"
    assert comp["vulnerabilities"][0]["cvss"]["base_score"] == 9.8
    assert comp["vulnerabilities"][0]["cvss"]["severity"] == "CRITICAL"


def test_locs_json_shape(tmp_path: Path) -> None:
    reporter = Reporter(tmp_path, "proj")
    reporter.generate(_make_report())

    data = json.loads((tmp_path / "proj_locs.json").read_text(encoding="utf-8"))
    assert data[0]["component"] == "foo"
    assert data[0]["file"] == "sbom.json"


def test_license_json_classification(tmp_path: Path) -> None:
    reporter = Reporter(tmp_path, "proj")
    reporter.generate(_make_report(), print_licenses=True)

    data = json.loads((tmp_path / "proj_license.json").read_text(encoding="utf-8"))
    assert data["Low"] == ["MIT"]
    assert data["Medium"] == []
    assert data["High"] == []
    assert data["Unmapped"] == []


def test_report_without_cvss_is_unassessed(tmp_path: Path) -> None:
    vuln = Vulnerability(id="OSV-2", source="OSV", summary="no cvss")
    comp = Component(name="baz", version="1.0", purl="pkg:pypi/baz@1.0", vulnerabilities=[vuln])
    report = Report(project_name="proj", components=[comp], locations=[], licenses=[])

    reporter = Reporter(tmp_path, "proj")
    reporter.generate(report)

    text = (tmp_path / "proj_report.txt").read_text(encoding="utf-8")
    assert "UNASSESSED" in text
    data = json.loads((tmp_path / "proj_vulns.json").read_text(encoding="utf-8"))
    assert "cvss" not in data[0]["vulnerabilities"][0]
