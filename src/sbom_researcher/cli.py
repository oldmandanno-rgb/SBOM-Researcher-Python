"""CLI entry point for SBOM-Researcher."""

from __future__ import annotations

from pathlib import Path

import click
import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .models import Component, Report
from .osv_client import OSVClient
from .parser import SBOMParser
from .reporter import Reporter

console = Console()


@click.command()
@click.option("--sbom-path", "-s", required=True, type=click.Path(exists=True, path_type=Path), help="Path to SBOM file or directory")
@click.option("--output-dir", "-o", required=True, type=click.Path(path_type=Path), help="Output directory for reports")
@click.option("--project-name", "-p", required=True, help="Project name for report files")
@click.option("--min-score", "-m", default=0.0, type=float, help="Minimum CVSS score to report (0-10)")
@click.option("--list-all", "-a", is_flag=True, help="List all components even without vulnerabilities")
@click.option("--print-licenses", "-l", is_flag=True, help="Include license classification in report")
def main(sbom_path: Path, output_dir: Path, project_name: str, min_score: float, list_all: bool, print_licenses: bool) -> None:
    """Analyze SBOMs for vulnerabilities via OSV.dev."""
    console.print(f"[bold blue]SBOM-Researcher-Python[/bold blue] - Project: {project_name}")
    console.print(f"SBOM Path: {sbom_path}")
    console.print(f"Output Dir: {output_dir}")
    console.print(f"Min Score: {min_score}")

    # Parse SBOMs
    parser = SBOMParser()
    all_components: list[Component] = []
    all_locations: list = []
    all_licenses: list = []

    sbom_files = []
    if sbom_path.is_dir():
        sbom_files = list(sbom_path.glob("*.json"))
    else:
        sbom_files = [sbom_path]

    console.print(f"Found {len(sbom_files)} SBOM file(s)")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("Parsing SBOMs...", total=len(sbom_files))
        for sbom_file in sbom_files:
            try:
                components, locations, licenses = parser.parse(sbom_file)
                all_components.extend(components)
                all_locations.extend(locations)
                all_licenses.extend(licenses)
                console.print(f"  ✓ {sbom_file.name}: {len(components)} components")
            except OSError as e:
                console.print(f"  ✗ {sbom_file.name}: {e}")
            progress.advance(task)

    # Deduplicate components by purl
    seen = set()
    unique_components = []
    for comp in all_components:
        if comp.purl not in seen:
            seen.add(comp.purl)
            unique_components.append(comp)

    console.print(f"Total unique components: {len(unique_components)}")

    # Query OSV
    with OSVClient() as osv, Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("Querying OSV...", total=len(unique_components))
        for comp in unique_components:
            try:
                response = osv.query(comp.purl)
                vulns = osv.parse_vulnerabilities(comp, response, min_score)
                comp.vulnerabilities = vulns

                # Set recommendation (highest fixed version)
                fixed_versions = [v.fixed_version for v in vulns if v.fixed_version]
                if fixed_versions:
                    from packaging import version as pkg_version
                    _parser = SBOMParser()
                    def version_key(v: str, p: SBOMParser = _parser) -> pkg_version.Version:
                        try:
                            return pkg_version.parse(v)
                        except pkg_version.InvalidVersion:
                            # Fallback: normalize version string (port of ConvertTo-Version)
                            return pkg_version.parse(p.convert_to_version(v))
                    comp.recommendation = max(fixed_versions, key=version_key)
            except (httpx.HTTPError, ValueError) as e:
                console.print(f"  Error querying {comp.purl}: {e}")
            progress.advance(task)

    # Build report
    report = Report(
        project_name=project_name,
        components=unique_components,
        locations=all_locations,
        licenses=all_licenses
    )

    # Generate reports
    reporter = Reporter(output_dir, project_name)
    reporter.generate(report, list_all=list_all, print_licenses=print_licenses)

    # Summary
    vuln_count = sum(len(c.vulnerabilities) for c in unique_components)
    comp_with_vulns = sum(1 for c in unique_components if c.vulnerabilities)
    console.print("\n[bold green]Done![/bold green]")
    console.print(f"Components with vulnerabilities: {comp_with_vulns}")
    console.print(f"Total vulnerabilities found: {vuln_count}")
    console.print(f"Reports written to: {output_dir}")


if __name__ == "__main__":
    main()