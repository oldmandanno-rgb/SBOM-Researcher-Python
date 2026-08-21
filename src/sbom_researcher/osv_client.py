"""OSV.dev API client for vulnerability queries."""

from __future__ import annotations

import os
from typing import Any

import httpx
from packaging import version as pkg_version
from typing_extensions import Self

from .models import Component, CVSSBreakdown, Vulnerability


class OSVClient:
    """Client for querying OSV.dev vulnerability database."""

    BASE_URL = "https://api.osv.dev/v1/query"

    def __init__(self, timeout: float = 30.0, base_url: str | None = None) -> None:
        self.client = httpx.Client(timeout=timeout)
        # Explicit arg wins; otherwise allow an env override (handy for pointing
        # the client at a local osv_service mirror during development/testing).
        self.base_url = base_url or os.environ.get("OSV_API_BASE_URL", self.BASE_URL)

    def query(self, purl: str) -> dict[str, Any]:
        """Query OSV for vulnerabilities affecting a package."""
        # OSV uses "crates.io" not "cargo" for Rust packages
        query_purl = purl.replace(":cargo/", ":crates.io/")

        body = {"package": {"purl": query_purl}}
        response = self.client.post(self.base_url, json=body)
        response.raise_for_status()
        return response.json()  # type: ignore[no-any-return]

    def parse_vulnerabilities(self, component: Component, osv_response: dict, min_score: float = 0.0) -> list[Vulnerability]:
        """Parse OSV response into Vulnerability objects."""
        vulns = []
        for vuln_data in osv_response.get("vulns", []):
            vuln = self._parse_single(vuln_data)
            if vuln:
                # Filter by min_score if scored
                if vuln.score is not None and vuln.score < min_score:
                    continue
                vulns.append(vuln)
        return vulns

    def _parse_single(self, vuln_data: dict) -> Vulnerability | None:
        """Parse a single OSV vulnerability entry."""
        vuln_id = vuln_data.get("id", "")
        summary = vuln_data.get("summary")
        details = vuln_data.get("details")

        # Extract fixed version
        fixed_version = self._extract_fixed_version(vuln_data)

        # Parse CVSS
        cvss = self._parse_cvss(vuln_data)

        vuln = Vulnerability(
            id=vuln_id,
            summary=summary,
            details=details,
            fixed_version=fixed_version,
            cvss=cvss,
            score=cvss.base_score if cvss else None,
            severity=cvss.severity if cvss else None
        )
        return vuln

    def _extract_fixed_version(self, vuln_data: dict) -> str | None:
        """Extract the highest fixed version from affected ranges."""
        fixed_versions = []
        for affected in vuln_data.get("affected", []):
            for range_data in affected.get("ranges", []):
                if range_data.get("type") == "GIT":
                    continue
                for event in range_data.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

        if not fixed_versions:
            return None

        # Return highest version
        try:
            result = max(fixed_versions, key=lambda v: pkg_version.parse(v))
            return str(result)
        except pkg_version.InvalidVersion:
            return fixed_versions[0] if fixed_versions else None

    def _parse_cvss(self, vuln_data: dict) -> CVSSBreakdown | None:
        """Parse CVSS data from OSV response."""
        severities = vuln_data.get("severity", [])
        if not severities:
            return None

        # Prefer CVSS v4.0, then 3.1, then 3.0
        for sev in severities:
            score_str = sev.get("score", "")
            if score_str.startswith("CVSS:4.0"):
                return self._parse_cvss4(score_str)
            elif score_str.startswith("CVSS:3.1"):
                return self._parse_cvss3(score_str, "3.1")
            elif score_str.startswith("CVSS:3.0"):
                return self._parse_cvss3(score_str, "3.0")

        # Fallback to first
        first = severities[0]
        score_str = first.get("score", "")
        if score_str.startswith("CVSS:"):
            if "4.0" in score_str:
                return self._parse_cvss4(score_str)
            return self._parse_cvss3(score_str, "3.1")

        return None

    def _parse_cvss3(self, vector: str, version: str) -> CVSSBreakdown:
        """Parse CVSS v3.x vector."""
        # Use cvss library for calculation
        from cvss import CVSS3  # type: ignore[import-untyped]
        cvss_obj = CVSS3(vector)
        score = cvss_obj.scores()[0]

        parts = vector.split("/")
        metrics = {}
        for p in parts[1:]:
            k, v = p.split(":", 1)
            metrics[k] = v

        return CVSSBreakdown(
            vector=vector,
            version=version,
            base_score=round(score, 1),
            severity=self._severity_from_score(score),
            attack_vector=metrics.get("AV"),
            attack_complexity=metrics.get("AC"),
            privileges_required=metrics.get("PR"),
            user_interaction=metrics.get("UI"),
            scope=metrics.get("S"),
            confidentiality=metrics.get("C"),
            integrity=metrics.get("I"),
            availability=metrics.get("A"),
            score_url=f"https://www.first.org/cvss/calculator/{version}#{vector}"
        )

    def _parse_cvss4(self, vector: str) -> CVSSBreakdown:
        """Parse CVSS v4.0 vector."""
        from cvss import CVSS4
        cvss_obj = CVSS4(vector)
        score = cvss_obj.scores()[0]

        parts = vector.split("/")
        metrics = {}
        for p in parts[1:]:
            k, v = p.split(":", 1)
            metrics[k] = v

        return CVSSBreakdown(
            vector=vector,
            version="4.0",
            base_score=round(score, 1),
            severity=self._severity_from_score(score),
            attack_vector=metrics.get("AV"),
            attack_complexity=metrics.get("AC"),
            privileges_required=metrics.get("PR"),
            user_interaction=metrics.get("UI"),
            scope=None,  # v4.0 uses different metrics
            confidentiality=metrics.get("VC"),
            integrity=metrics.get("VI"),
            availability=metrics.get("VA"),
            score_url=f"https://www.first.org/cvss/calculator/4.0#{vector}"
        )

    def _severity_from_score(self, score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        return "NONE"

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()