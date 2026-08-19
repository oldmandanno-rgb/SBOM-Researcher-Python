"""Data models for SBOM components, vulnerabilities, and reports."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
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
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality: Optional[str] = None
    integrity: Optional[str] = None
    availability: Optional[str] = None
    score_url: Optional[str] = None


@dataclass
class Vulnerability:
    """Single vulnerability finding."""
    id: str
    source: str = "OSV"
    summary: Optional[str] = None
    details: Optional[str] = None
    fixed_version: Optional[str] = None
    cvss: Optional[CVSSBreakdown] = None
    score: Optional[float] = None
    severity: Optional[str] = None


@dataclass
class Component:
    """SBOM component with vulnerabilities."""
    name: str
    version: str
    purl: str
    license: str = "NOASSERTION"
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    recommendation: Optional[str] = None  # Highest fixed version


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