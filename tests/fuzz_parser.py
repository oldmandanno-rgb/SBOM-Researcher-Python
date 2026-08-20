#!/usr/bin/env python3
"""Fuzz target for SBOM parser using Atheris."""

import sys
import tempfile
import json
from pathlib import Path
import atheris

from sbom_researcher.parser import SBOMParser


def generate_cyclonedx_sbom(fdp: atheris.FuzzedDataProvider) -> dict:
    """Generate a random CycloneDX SBOM."""
    num_components = fdp.ConsumeIntInRange(0, 10)
    components = []
    for _ in range(num_components):
        comp = {
            "type": fdp.PickValueInList(["library", "framework", "application"]),
            "name": fdp.ConsumeUnicodeNoSurrogates(20),
            "version": fdp.ConsumeUnicodeNoSurrogates(10),
        }
        if fdp.ConsumeBool():
            comp["purl"] = f"pkg:pypi/{fdp.ConsumeUnicodeNoSurrogates(10)}@{fdp.ConsumeUnicodeNoSurrogates(10)}"
        if fdp.ConsumeBool():
            comp["licenses"] = [{"license": {"id": fdp.ConsumeUnicodeNoSurrogates(15)}}]
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
    }


def generate_spdx_sbom(fdp: atheris.FuzzedDataProvider) -> dict:
    """Generate a random SPDX SBOM."""
    num_packages = fdp.ConsumeIntInRange(0, 10)
    packages = []
    for _ in range(num_packages):
        pkg = {
            "name": fdp.ConsumeUnicodeNoSurrogates(20),
            "versionInfo": fdp.ConsumeUnicodeNoSurrogates(10),
        }
        if fdp.ConsumeBool():
            pkg["externalRefs"] = [{
                "referenceType": "purl",
                "referenceLocator": f"pkg:npm/{fdp.ConsumeUnicodeNoSurrogates(10)}@{fdp.ConsumeUnicodeNoSurrogates(10)}"
            }]
        if fdp.ConsumeBool():
            pkg["licenseDeclared"] = fdp.ConsumeUnicodeNoSurrogates(15)
        packages.append(pkg)

    return {
        "spdxVersion": "SPDX-2.3",
        "packages": packages,
    }


def TestOneInput(data: bytes) -> None:
    """Atheris fuzz entry point."""
    fdp = atheris.FuzzedDataProvider(data)

    parser = SBOMParser()

    try:
        # Randomly choose SBOM format
        if fdp.ConsumeBool():
            sbom_data = generate_cyclonedx_sbom(fdp)
        else:
            sbom_data = generate_spdx_sbom(fdp)

        # Write to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_data, f)
            temp_path = f.name

        # Parse - this exercises the main parse() method
        parser.parse(Path(temp_path))

    except Exception:
        # Ignore all exceptions - we're looking for crashes
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()