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
import os
import json
import tempfile
import atheris
from pathlib import Path

with atheris.instrument_imports():
    from sbom_researcher.parser import SBOMParser


def _run_on_text(text: str) -> None:
    parser = Parser()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        tf.write(text)
        tf.flush()
        path = tf.name
    try:
        parser.parse(Path(path), track_locations=False)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Fuzz the CycloneDX parsing path with a fuzzed document.
    try:
        content = {
            "bomFormat": "CycloneDX",
            "specVersion": fdp.ConsumeUnicodeNoSurrogates(10),
            "version": fdp.ConsumeIntInRange(0, 5),
            "components": [],
        }
        for _ in range(fdp.ConsumeIntInRange(0, 5)):
            content["components"].append({
                "type": fdp.ConsumeUnicodeNoSurrogates(10),
                "name": fdp.ConsumeUnicodeNoSurrogates(20),
                "version": fdp.ConsumeUnicodeNoSurrogates(10),
                "purl": f"pkg:pypi/{fdp.ConsumeUnicodeNoSurrogates(10)}@{fdp.ConsumeUnicodeNoSurrogates(10)}",
                "licenses": [{"license": {"id": fdp.ConsumeUnicodeNoSurrogates(15)}}],
            })
        _run_on_text(json.dumps(content))
    except Exception:
        pass

    # Fuzz the SPDX parsing path with a fuzzed document.
    try:
        content = {
            "spdxVersion": fdp.ConsumeUnicodeNoSurrogates(10),
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": fdp.ConsumeUnicodeNoSurrogates(20),
            "documentNamespace": "https://example.org/test",
            "packages": [],
        }
        for _ in range(fdp.ConsumeIntInRange(0, 5)):
            content["packages"].append({
                "name": fdp.ConsumeUnicodeNoSurrogates(20),
                "SPDXID": f"SPDXRef-Package-{fdp.ConsumeInt(1000)}",
                "downloadLocation": "NOASSERTION",
                "versionInfo": fdp.ConsumeUnicodeNoSurrogates(10),
                "licenseConcluded": fdp.ConsumeUnicodeNoSurrogates(15),
                "licenseDeclared": fdp.ConsumeUnicodeNoSurrogates(15),
                "copyrightText": "NOASSERTION",
            })
        _run_on_text(json.dumps(content))
    except Exception:
        pass

    # Fuzz the raw JSON / format-detection path with arbitrary input.
    try:
        _run_on_text(data.decode("utf-8", errors="replace"))
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
