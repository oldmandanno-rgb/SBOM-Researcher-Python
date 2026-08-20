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
    from sbom_researcher.osv_client import parse_vulnerability, extract_affected_versions
    import json


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Fuzz parse_vulnerability
    try:
        vuln_data = {
            "id": fdp.ConsumeUnicodeNoSurrogates(20),
            "summary": fdp.ConsumeUnicodeNoSurrogates(50),
            "details": fdp.ConsumeUnicodeNoSurrogates(100),
            "aliases": [fdp.ConsumeUnicodeNoSurrogates(15) for _ in range(fdp.ConsumeIntInRange(0, 3))],
            "modified": "2023-01-01T00:00:00Z",
            "published": "2023-01-01T00:00:00Z",
            "database_specific": {
                "severity": fdp.ConsumeUnicodeNoSurrogates(10)
            }
        }
        json_str = json.dumps(vuln_data)
        parse_vulnerability(json_str)
    except Exception:
        pass

    # Fuzz extract_affected_versions
    try:
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
        extract_affected_versions(affected)
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()