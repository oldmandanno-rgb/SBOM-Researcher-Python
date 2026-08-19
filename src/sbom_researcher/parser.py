"""SBOM parsing for CycloneDX and SPDX formats."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
from cyclonedx.model.bom import Bom
from cyclonedx.parser import parse_from_json as parse_cyclonedx_json
from spdx_tools.spdx.parser.parse_anything import parse_file as parse_spdx

from .models import Component, ComponentLocation, LicenseInfo, LicenseAction


class SBOMParser:
    """Parse CycloneDX and SPDX SBOMs into internal models."""

    LOW_ACTION_LICENSES = {
        "GFDL-1.3-or-later", "GFDL-1.3-only", "GFDL-1.2-or-later", "GFDL-1.2-only",
        "Apache", "Apache 2.0", "GNU", "MIT", "MIT License", "Apache-2.0", "ISC",
        "BSD", "BSD-4-Clause", "BSD-3", "BSD-3-Clause", "BSD-2-Clause", "BSD-1-Clause",
        "BSD-4-Clause-UC", "Unlicense", "Zlib", "Libpng", "Wtfpl-2.0", "OFL-1.1",
        "Edl-v10", "CCA-4.0", "0BSD", "CC0", "CC0-1.0", "BSD-2-Clause-NetBSD",
        "Beerware", "PostgreSQL", "OpenSSL", "W3C", "HPND", "curl", "NTP", "WTFPL"
    }

    MED_ACTION_LICENSES = {
        "IPL-1.0", "EPL-2.0", "MPL-1.0", "MPL-1.1", "MPL-2.0", "EPL-1.0",
        "CDDL-1.1", "AFL-2.1", "CPL-1.0", "CC-BY-4.0", "Artistic", "Artistic-2.0",
        "CC-BY-3.0", "AFL-3.0", "BSL-1.0", "OLDAP-2.8", "Python-2.0", "Ruby",
        "X11", "PSF-2.0", "Python", "Python Software Foundation License"
    }

    HIGH_ACTION_LICENSES = {
        "AGPL-3.0-or-later", "AGPL-3.0-only", "GPL-1.0-or-later", "GPL-3.0-only",
        "GPL-1.0-only", "LGPL-2.1-only", "LGPL-2.0-only", "LGPL-3.0-only", "GPL",
        "LGPL", "LGPL-2.0-or-later", "LGPL-2.1-or-later", "GPL-2.0-or-later",
        "GPL-2.0-only", "GPL-3.0-or-later", "GPL-2.0+", "GPLv2+", "GPL-2.1+",
        "GPL-3.0+", "LGPL-2.0", "LGPL-2.0+", "LGPL-2.1", "LGPL-2.1+", "LGPL-3.0",
        "LGPL-3.0+", "GPL-2.0", "CC-BY-3.0-US", "CC-BY-SA-3.0", "GFDL-1.2",
        "GFDL-1.3", "GPL-3.0", "GPL-1.0", "GPL-1.0+", "IJG", "AGPL-3.0",
        "CC-BY-SA-4.0"
    }

    def __init__(self):
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

        bom = parse_cyclonedx_json(str(sbom_path))
        for comp in bom.components or []:
            if comp.type not in ("library", "framework"):
                continue

            if not comp.purl:
                continue

            purl = str(comp.purl)
            if purl in self.seen_purls:
                continue
            self.seen_purls.add(purl)

            name, version = self.extract_purl_info(purl)
            if not name or not version:
                continue

            # License
            license_id = "NOASSERTION"
            if comp.licenses:
                lic = comp.licenses[0]
                if lic.license and lic.license.id:
                    license_id = lic.license.id
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