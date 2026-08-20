"""SBOM parsing for CycloneDX and SPDX formats."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import ClassVar
from urllib.parse import unquote

from .models import Component, ComponentLocation, LicenseAction, LicenseInfo


class SBOMParser:
    """Parse CycloneDX and SPDX SBOMs into internal models."""

    LOW_ACTION_LICENSES: ClassVar[set[str]] = {
        "GFDL-1.3-or-later", "GFDL-1.3-only", "GFDL-1.2-or-later", "GFDL-1.2-only",
        "Apache", "Apache 2.0", "GNU", "MIT", "MIT License", "Apache-2.0", "ISC",
        "BSD", "BSD-4-Clause", "BSD-3", "BSD-3-Clause", "BSD-2-Clause", "BSD-1-Clause",
        "BSD-4-Clause-UC", "Unlicense", "Zlib", "Libpng", "Wtfpl-2.0", "OFL-1.1",
        "Edl-v10", "CCA-4.0", "0BSD", "CC0", "CC0-1.0", "BSD-2-Clause-NetBSD",
        "Beerware", "PostgreSQL", "OpenSSL", "W3C", "HPND", "curl", "NTP", "WTFPL"
    }

    MED_ACTION_LICENSES: ClassVar[set[str]] = {
        "IPL-1.0", "EPL-2.0", "MPL-1.0", "MPL-1.1", "MPL-2.0", "EPL-1.0",
        "CDDL-1.1", "AFL-2.1", "CPL-1.0", "CC-BY-4.0", "Artistic", "Artistic-2.0",
        "CC-BY-3.0", "AFL-3.0", "BSL-1.0", "OLDAP-2.8", "Python-2.0", "Ruby",
        "X11", "PSF-2.0", "Python", "Python Software Foundation License"
    }

    HIGH_ACTION_LICENSES: ClassVar[set[str]] = {
        "AGPL-3.0-or-later", "AGPL-3.0-only", "GPL-1.0-or-later", "GPL-3.0-only",
        "GPL-1.0-only", "LGPL-2.1-only", "LGPL-2.0-only", "LGPL-3.0-only", "GPL",
        "LGPL", "LGPL-2.0-or-later", "LGPL-2.1-or-later", "GPL-2.0-or-later",
        "GPL-2.0-only", "GPL-3.0-or-later", "GPL-2.0+", "GPLv2+", "GPL-2.1+",
        "GPL-3.0+", "LGPL-2.0", "LGPL-2.0+", "LGPL-2.1", "LGPL-2.1+", "LGPL-3.0",
        "LGPL-3.0+", "GPL-2.0", "CC-BY-3.0-US", "CC-BY-SA-3.0", "GFDL-1.2",
        "GFDL-1.3", "GPL-3.0", "GPL-1.0", "GPL-1.0+", "IJG", "AGPL-3.0",
        "CC-BY-SA-4.0"
    }

    def __init__(self) -> None:
        self.seen_purls: set[str] = set()

    def classify_license(self, license_id: str) -> LicenseAction:
        """Classify license by action required."""
        if license_id in self.LOW_ACTION_LICENSES:
            return LicenseAction.LOW
        if license_id in self.MED_ACTION_LICENSES:
            return LicenseAction.MEDIUM
        if license_id in self.HIGH_ACTION_LICENSES:
            return LicenseAction.HIGH
        return LicenseAction.UNMAPPED

    def extract_purl_info(self, purl: str) -> tuple[str, str]:
        """Extract name and version from purl."""
        # pkg:type/name@version
        if "@" not in purl:
            return "", ""
        prefix, version_part = purl.split("@", 1)
        version = version_part.split("?")[0]  # strip qualifiers
        name = prefix.split("/")[-1]
        return name, version

    def test_purl_format(self, purl: str) -> bool:
        """Validate purl format per original Test-PurlFormat."""
        # Original regex: ^pkg:[a-z0-9-]+/([a-zA-Z0-9._~-]+/?)+@([v0-9]+\.(\*|[0-9]+)\.(\*|[0-9]+)([+-][a-zA-Z0-9._-]+)?)$
        purl_decoded = unquote(purl)
        purl_regex = r'^pkg:[a-z0-9-]+/([a-zA-Z0-9._~-]+/?)+@([v0-9]+\.(\*|[0-9]+)\.(\*|[0-9]+)([+-][a-zA-Z0-9._-]+)?)$'
        return bool(re.match(purl_regex, purl_decoded))

    def convert_to_version(self, version_string: str) -> str:
        """Normalize version string by splitting on non-digit/dot and rejoining.
        
        Port of original ConvertTo-Version function.
        """
        # Split the string by dot or any non-digit character
        parts = re.split(r'[\.\D]+', version_string)
        # Filter out empty parts and join with dots
        parts = [p for p in parts if p]
        return ".".join(parts)

    def parse(self, sbom_path: Path, track_locations: bool = True) -> tuple[list[Component], list[ComponentLocation], list[LicenseInfo]]:
        """Parse SBOM file, return (components, locations, licenses)."""
        content = sbom_path.read_text()
        data = json.loads(content)

        # Detect format
        if "components" in data and "bomFormat" in data and data["bomFormat"] == "CycloneDX":
            return self._parse_cyclonedx(data, sbom_path, track_locations)
        elif "packages" in data and "spdxVersion" in data:
            return self._parse_spdx(data, sbom_path, track_locations)
        else:
            raise ValueError(f"Unsupported SBOM format: {sbom_path}")

    def _parse_cyclonedx(self, data: dict, sbom_path: Path, track_locations: bool) -> tuple[list[Component], list[ComponentLocation], list[LicenseInfo]]:
        components = []
        locations = []
        licenses_map: dict[str, LicenseAction] = {}

        for comp in data.get("components", []):
            if comp.get("type") not in ("library", "framework"):
                continue

            purl = comp.get("purl")
            if not purl:
                continue
            if purl in self.seen_purls:
                continue
            self.seen_purls.add(purl)

            name, version = self.extract_purl_info(purl)
            if not name or not version:
                continue

            # License
            license_id = "NOASSERTION"
            licenses = comp.get("licenses", [])
            if licenses:
                lic = licenses[0]
                if lic.get("license", {}).get("id"):
                    license_id = lic["license"]["id"]
                    licenses_map[license_id] = self.classify_license(license_id)

            component = Component(
                name=name,
                version=version,
                purl=purl,
                license=license_id
            )
            components.append(component)

            if track_locations:
                locations.append(ComponentLocation(
                    component=name,
                    version=version,
                    file=str(sbom_path)
                ))

        license_infos = [LicenseInfo(name=k, action=v) for k, v in licenses_map.items()]
        return components, locations, license_infos

    def _parse_spdx(self, data: dict, sbom_path: Path, track_locations: bool) -> tuple[list[Component], list[ComponentLocation], list[LicenseInfo]]:
        components = []
        locations = []
        licenses_map: dict[str, LicenseAction] = {}

        for pkg in data.get("packages", []):
            # Find purl in externalRefs
            purl = None
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
                    break

            if not purl or purl in self.seen_purls:
                continue
            self.seen_purls.add(purl)

            name, version = self.extract_purl_info(purl)
            if not name:
                name = pkg.get("name", "")
            if not version:
                version = pkg.get("versionInfo", "")

            if not name or not version:
                continue

            # License
            license_id = pkg.get("licenseDeclared") or pkg.get("licenseConcluded") or "NOASSERTION"
            if license_id and license_id != "NOASSERTION":
                licenses_map[license_id] = self.classify_license(license_id)

            component = Component(
                name=name,
                version=version,
                purl=purl,
                license=license_id
            )
            components.append(component)

            if track_locations:
                locations.append(ComponentLocation(
                    component=name,
                    version=version,
                    file=str(sbom_path)
                ))

        license_infos = [LicenseInfo(name=k, action=v) for k, v in licenses_map.items()]
        return components, locations, license_infos