"""Report generation for text and JSON outputs."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import LicenseAction, Report


class Reporter:
    """Generate text and JSON reports."""

    def __init__(self, output_dir: Path, project_name: str):
        self.output_dir = output_dir
        self.project_name = project_name
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.console = Console(record=True)

    def generate(self, report: Report, list_all: bool = False, print_licenses: bool = False) -> None:
        """Generate all report files."""
        # Text report
        text_path = self.output_dir / f"{self.project_name}_report.txt"
        self._generate_text_report(report, text_path, list_all, print_licenses)

        # JSON reports
        vuln_path = self.output_dir / f"{self.project_name}_vulns.json"
        loc_path = self.output_dir / f"{self.project_name}_locs.json"
        license_path = self.output_dir / f"{self.project_name}_license.json"

        self._generate_vuln_json(report, vuln_path)
        self._generate_loc_json(report, loc_path)
        if print_licenses:
            self._generate_license_json(report, license_path)

    def _generate_text_report(self, report: Report, path: Path, list_all: bool, print_licenses: bool) -> None:
        """Generate human-readable text report."""
        with path.open("w") as f:
            f.write(f"SBOM-Researcher Report for Project: {self.project_name}\n")
            f.write("=" * 80 + "\n\n")

            # Components with vulnerabilities
            vuln_components = [c for c in report.components if c.vulnerabilities]
            for comp in vuln_components:
                f.write("-" * 60 + "\n")
                f.write(f"-   Component: {comp.name} {comp.version}\n")
                f.write("-" * 60 + "\n")
                f.write(f"License info:  {comp.license}\n\n")

                for vuln in comp.vulnerabilities:
                    f.write(f"Vulnerability: {vuln.id}\n")
                    f.write(f"Source: {vuln.source}\n")
                    if vuln.summary:
                        f.write(f"Summary: {vuln.summary}\n")
                    if vuln.details:
                        f.write(f"Details: {vuln.details}\n")
                    f.write(f"Fixed Version: {vuln.fixed_version or 'UNSET'}\n")

                    if vuln.cvss:
                        f.write(f"Score page: {vuln.cvss.score_url}\n")
                        f.write(f"CVSS Breakdown: {vuln.cvss.vector}\n")
                        f.write(f"CVSS Base Score: {vuln.cvss.base_score}\n")
                        f.write(f"CVSS Severity: {vuln.cvss.severity}\n")
                        if vuln.cvss.attack_vector:
                            f.write(f"CVSS Attack Vector: {vuln.cvss.attack_vector}\n")
                        if vuln.cvss.attack_complexity:
                            f.write(f"CVSS Attack Complexity: {vuln.cvss.attack_complexity}\n")
                        if vuln.cvss.privileges_required:
                            f.write(f"CVSS Privileges Required: {vuln.cvss.privileges_required}\n")
                        if vuln.cvss.user_interaction:
                            f.write(f"CVSS User Interaction: {vuln.cvss.user_interaction}\n")
                        if vuln.cvss.scope:
                            f.write(f"CVSS Scope: {vuln.cvss.scope}\n")
                        if vuln.cvss.confidentiality:
                            f.write(f"CVSS Confidentiality Impact: {vuln.cvss.confidentiality}\n")
                        if vuln.cvss.integrity:
                            f.write(f"CVSS Integrity Impact: {vuln.cvss.integrity}\n")
                        if vuln.cvss.availability:
                            f.write(f"CVSS Availability Impact: {vuln.cvss.availability}\n")
                    else:
                        f.write("CVSS Breakdown: CVSS score currently UNASSESSED\n")

                    f.write("\n")

                if comp.recommendation:
                    f.write("##############\n")
                    f.write(f"-   Recommended Version to upgrade to that addresses all {comp.name} {comp.version} vulnerabilities: {comp.recommendation}\n")
                    f.write("##############\n")

            # Summary table
            f.write("\n" + "=" * 60 + "\n")
            f.write("= List of all components with vulnerabilities and their SBOM file\n")
            f.write("=" * 60 + "\n")

            table = Table()
            table.add_column("Component")
            table.add_column("Version")
            table.add_column("File")
            for loc in report.locations:
                table.add_row(loc.component, loc.version, loc.file)
            self.console.print(table)
            f.write(self.console.export_text())

            # Licenses
            if print_licenses and report.licenses:
                f.write("\n" + "-" * 60 + "\n")
                for action in [LicenseAction.LOW, LicenseAction.MEDIUM, LicenseAction.HIGH, LicenseAction.UNMAPPED]:
                    licenses = [l.name for l in report.licenses if l.action == action]
                    if licenses:
                        f.write(f"-   {action.value} Action Licenses: {'  '.join(licenses)}\n")
                f.write("-" * 60 + "\n")

            # List all components if requested
            if list_all:
                f.write("\nAll components evaluated:\n")
                for comp in report.components:
                    f.write(f"  {comp.name} {comp.version} - {comp.license}\n")

    def _generate_vuln_json(self, report: Report, path: Path) -> None:
        """Generate vulnerabilities JSON."""
        data: list[dict] = []
        for comp in report.components:
            if comp.vulnerabilities:
                comp_data: dict[str, object] = {
                    "name": comp.name,
                    "version": comp.version,
                    "purl": comp.purl,
                    "license": comp.license,
                    "recommendation": comp.recommendation,
                    "vulnerabilities": []
                }
                vulnerabilities_list: list[dict[str, object]] = comp_data["vulnerabilities"]  # type: ignore[assignment]
                for vuln in comp.vulnerabilities:
                    vuln_data: dict[str, object] = {
                        "id": vuln.id,
                        "source": vuln.source,
                        "summary": vuln.summary,
                        "details": vuln.details,
                        "fixed_version": vuln.fixed_version,
                        "score": vuln.score,
                        "severity": vuln.severity
                    }
                    if vuln.cvss:
                        vuln_data["cvss"] = {
                            "vector": vuln.cvss.vector,
                            "version": vuln.cvss.version,
                            "base_score": vuln.cvss.base_score,
                            "severity": vuln.cvss.severity,
                            "score_url": vuln.cvss.score_url
                        }
                    vulnerabilities_list.append(vuln_data)
                data.append(comp_data)

        with path.open("w") as f:
            json.dump(data, f, indent=2)

    def _generate_loc_json(self, report: Report, path: Path) -> None:
        """Generate component locations JSON."""
        data = [
            {"component": loc.component, "version": loc.version, "file": loc.file}
            for loc in report.locations
        ]
        with path.open("w") as f:
            json.dump(data, f, indent=2)

    def _generate_license_json(self, report: Report, path: Path) -> None:
        """Generate license classification JSON."""
        data = {
            "Low": [l.name for l in report.licenses if l.action == LicenseAction.LOW],
            "Medium": [l.name for l in report.licenses if l.action == LicenseAction.MEDIUM],
            "High": [l.name for l in report.licenses if l.action == LicenseAction.HIGH],
            "Unmapped": [l.name for l in report.licenses if l.action == LicenseAction.UNMAPPED]
        }
        with path.open("w") as f:
            json.dump(data, f, indent=2)