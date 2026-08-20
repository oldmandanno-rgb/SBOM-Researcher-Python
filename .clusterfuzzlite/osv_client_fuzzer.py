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
import json

with atheris.instrument_imports():
    from sbom_researcher.osv_client import OSVClient
    from sbom_researcher.models import Component


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Fuzz _parse_cvss via OSVClient
    try:
        client = OSVClient()
        vuln_data = {
            "id": fdp.ConsumeUnicodeNoSurrogates(20),
            "summary": fdp.ConsumeUnicodeNoSurrogates(50),
            "details": fdp.ConsumeUnicodeNoSurrogates(100),
            "aliases": [fdp.ConsumeUnicodeNoSurrogates(15) for _ in range(fdp.ConsumeIntInRange(0, 3))],
            "modified": "2023-01-01T00:00:00Z",
            "published": "2023-01-01T00:00:00Z",
            "severity": [{"score": fdp.ConsumeUnicodeNoSurrogates(50)}],
        }
        client._parse_cvss(vuln_data)
    except Exception:
        pass

    # Fuzz _extract_fixed_version
    try:
        client = OSVClient()
        affected = [{
            "package": {
                "name": fdp.ConsumeUnicodeNoSurrogates(20),
                "ecosystem": "PyPI"
            },
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": fdp.ConsumeUnicodeNoSurrogates(10)},
                    {"fixed": fdp.ConsumeUnicodeNoSurrogates(10)}
                ]
            }]
        }]
        client._extract_fixed_version({"affected": affected})
    except Exception:
        pass

    # Fuzz parse_vulnerabilities with a mock component
    try:
        client = OSVClient()
        component = Component(
            name=fdp.ConsumeUnicodeNoSurrogates(20),
            version=fdp.ConsumeUnicodeNoSurrogates(10),
            purl=f"pkg:pypi/{fdp.ConsumeUnicodeNoSurrogates(10)}@{fdp.ConsumeUnicodeNoSurrogates(10)}",
            licenses=[],
            locations=[]
        )
        osv_response = {
            "vulns": [{
                "id": fdp.ConsumeUnicodeNoSurrogates(20),
                "summary": fdp.ConsumeUnicodeNoSurrogates(50),
                "details": fdp.ConsumeUnicodeNoSurrogates(100),
                "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [{
                    "package": {"name": "test", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0.0"}]}]
                }]
            }]
        }
        client.parse_vulnerabilities(component, osv_response)
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()