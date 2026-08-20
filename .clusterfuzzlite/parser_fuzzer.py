#!/usr/bin/env python3
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import atheris

with atheris.instrument_imports():
    from sbom_researcher.parser import parse_cyclonedx_json, parse_spdx_json
    import json


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Generate random JSON-like content
    try:
        # Try to create a minimal valid CycloneDX JSON
        content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": []
        }

        # Add some random components
        for _ in range(fdp.ConsumeIntInRange(0, 5)):
            content["components"].append({
                "type": "library",
                "name": fdp.ConsumeUnicodeNoSurrogates(20),
                "version": fdp.ConsumeUnicodeNoSurrogates(10),
                "purl": f"pkg:pypi/{fdp.ConsumeUnicodeNoSurrogates(10)}@{fdp.ConsumeUnicodeNoSurrogates(10)}"
            })

        json_str = json.dumps(content)
        parse_cyclonedx_json(json_str, "test.json")
    except Exception:
        pass

    try:
        # Try to create a minimal valid SPDX JSON
        content = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Test",
            "documentNamespace": "https://example.org/test",
            "packages": []
        }

        for _ in range(fdp.ConsumeIntInRange(0, 5)):
            content["packages"].append({
                "name": fdp.ConsumeUnicodeNoSurrogates(20),
                "SPDXID": f"SPDXRef-Package-{fdp.ConsumeInt(1000)}",
                "downloadLocation": "NOASSERTION",
                "versionInfo": fdp.ConsumeUnicodeNoSurrogates(10),
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION"
            })

        json_str = json.dumps(content)
        parse_spdx_json(json_str, "test.json")
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()