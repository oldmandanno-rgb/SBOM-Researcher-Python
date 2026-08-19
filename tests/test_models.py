"""Tests for SBOM-Researcher-Python."""

import pytest
from sbom_researcher.models import (
    Component, Vulnerability, CVSSBreakdown, LicenseInfo, LicenseAction,
    ComponentLocation, Report
)


def test_component_creation():
    comp = Component(
        name="test-lib",
        version="1.0.0",
        purl="pkg:pypi/test-lib@1.0.0",
        license="MIT"
    )
    assert comp.name == "test-lib"
    assert comp.version == "1.0.0"
    assert comp.license == "MIT"


def test_vulnerability_creation():
    vuln = Vulnerability(
        id="CVE-2023-1234",
        summary="Test vulnerability",
        fixed_version="1.0.1"
    )
    assert vuln.id == "CVE-2023-1234"
    assert vuln.fixed_version == "1.0.1"


def test_license_classification():
    low = LicenseInfo(name="MIT", action=LicenseAction.LOW)
    high = LicenseInfo(name="GPL-3.0", action=LicenseAction.HIGH)
    assert low.action == LicenseAction.LOW
    assert high.action == LicenseAction.HIGH


def test_report_creation():
    report = Report(project_name="TestProject")
    assert report.project_name == "TestProject"
    assert report.components == []