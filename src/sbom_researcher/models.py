"""Data models for SBOM components, vulnerabilities, and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class LicenseAction(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNMAPPED = "UNMAPPED"


@dataclass
class LicenseInfo:
    """License classification result."""
    name: str
    action: LicenseAction = LicenseAction.UNMAPPED


@dataclass
class CVSSBreakdown:
    """CVSS vector component breakdown."""
    vector: str
    version: str  # "3.0", "3.1", "4.0"
    base_score: float
    severity: str
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    confidentiality: str | None = None
    integrity: str | None = None
    availability: str | None = None
    score_url: str | None = None


@dataclass
class Vulnerability:
    """Single vulnerability finding."""
    id: str
    source: str = "OSV"
    summary: str | None = None
    details: str | None = None
    fixed_version: str | None = None
    cvss: CVSSBreakdown | None = None
    score: float | None = None
    severity: str | None = None


@dataclass
class Component:
    """SBOM component with vulnerabilities."""
    name: str
    version: str
    purl: str
    license: str = "NOASSERTION"
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    recommendation: str | None = None  # Highest fixed version


@dataclass
class ComponentLocation:
    """Where a component was found."""
    component: str
    version: str
    file: str


@dataclass
class Report:
    """Complete analysis report."""
    project_name: str
    components: list[Component] = field(default_factory=list)
    locations: list[ComponentLocation] = field(default_factory=list)
    licenses: list[LicenseInfo] = field(default_factory=list)