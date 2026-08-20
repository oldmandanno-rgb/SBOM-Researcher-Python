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
    from sbom_researcher.reporter import generate_text_report, generate_vulns_json, generate_locs_json
    from sbom_researcher.models import Component, Vulnerability, CVSSBreakdown, Report, LicenseInfo
    import json


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Create a mock report with random data
    try:
        components = []
        for i in range(fdp.ConsumeIntInRange(0, 10)):
            components.append(Component(
                name=fdp.ConsumeUnicodeNoSurrogates(20),
                version=fdp.ConsumeUnicodeNoSurrogates(10),
                purl=f"pkg:pypi/{fdp.ConsumeUnicodeNoSurrogates(10)}@{fdp.ConsumeUnicodeNoSurrogates(10)}",
                licenses=[fdp.ConsumeUnicodeNoSurrogates(15)],
                locations=[f"file{i}.json"]
            ))

        vulnerabilities = []
        for i in range(fdp.ConsumeIntInRange(0, 5)):
            cvss = CVSSBreakdown(
                vector_string=fdp.ConsumeUnicodeNoSurrogates(50),
                base_score=fdp.ConsumeFloatInRange(0.0, 10.0),
                severity=fdp.ConsumeUnicodeNoSurrogates(10)
            )
            vulnerabilities.append(Vulnerability(
                id=fdp.ConsumeUnicodeNoSurrogates(20),
                summary=fdp.ConsumeUnicodeNoSurrogates(50),
                cvss=[cvss],
                affected_components=[fdp.ConsumeUnicodeNoSurrogates(20)]
            ))

        license_infos = []
        for i in range(fdp.ConsumeIntInRange(0, 5)):
            license_infos.append(LicenseInfo(
                spdx_id=fdp.ConsumeUnicodeNoSurrogates(15),
                name=fdp.ConsumeUnicodeNoSurrogates(20),
                classification=fdp.ConsumeUnicodeNoSurrogates(10)
            ))

        report = Report(
            project_name=fdp.ConsumeUnicodeNoSurrogates(20),
            components=components,
            vulnerabilities=vulnerabilities,
            license_infos=license_infos
        )

        # Test report generation
        generate_text_report(report, "test.txt")
        generate_vulns_json(report, "test_vulns.json")
        generate_locs_json(report, "test_locs.json")
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()