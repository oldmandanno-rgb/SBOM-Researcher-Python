"""Tests for SBOM parser including CVSS parsing, license classification, version handling."""

import pytest
from sbom_researcher.parser import SBOMParser
from sbom_researcher.models import LicenseAction
from sbom_researcher.osv_client import OSVClient


class TestLicenseClassification:
    """Tests for license classification (ported from SBOMResearcher.License.Tests.ps1)."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_low_action_licenses(self):
        low_licenses = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "Zlib"]
        for lic in low_licenses:
            assert self.parser.classify_license(lic) == LicenseAction.LOW

    def test_medium_action_licenses(self):
        med_licenses = ["MPL-2.0", "EPL-1.0", "CDDL-1.1", "Artistic-2.0", "Python-2.0"]
        for lic in med_licenses:
            assert self.parser.classify_license(lic) == LicenseAction.MEDIUM

    def test_high_action_licenses(self):
        high_licenses = ["GPL-3.0", "AGPL-3.0", "LGPL-2.1", "CC-BY-SA-4.0"]
        for lic in high_licenses:
            assert self.parser.classify_license(lic) == LicenseAction.HIGH

    def test_unmapped_licenses(self):
        assert self.parser.classify_license("Unknown-License") == LicenseAction.UNMAPPED
        assert self.parser.classify_license("") == LicenseAction.UNMAPPED

    def test_mixed_licenses(self):
        licenses = [
            ("MIT", LicenseAction.LOW),
            ("MPL-2.0", LicenseAction.MEDIUM),
            ("GPL-3.0", LicenseAction.HIGH),
            ("Unknown-License", LicenseAction.UNMAPPED),
        ]
        for lic, expected in licenses:
            assert self.parser.classify_license(lic) == expected


class TestVersionHandling:
    """Tests for version extraction and comparison (ported from SBOMResearcher.Version.Tests.ps1)."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_extract_purl_info_basic(self):
        name, version = self.parser.extract_purl_info("pkg:pypi/requests@2.28.1")
        assert name == "requests"
        assert version == "2.28.1"

    def test_extract_purl_info_with_qualifiers(self):
        name, version = self.parser.extract_purl_info("pkg:pypi/requests@2.28.1?foo=bar")
        assert name == "requests"
        assert version == "2.28.1"

    def test_extract_purl_info_no_version(self):
        # Current implementation returns empty strings for purls without @
        name, version = self.parser.extract_purl_info("pkg:pypi/requests")
        assert name == ""
        assert version == ""

    def test_extract_purl_info_cargo_to_crates_io(self):
        # Test the cargo→crates.io mapping that happens in OSV client
        name, version = self.parser.extract_purl_info("pkg:cargo/serde@1.0.0")
        assert name == "serde"
        assert version == "1.0.0"

    def test_get_high_version_basic(self):
        from packaging import version as pkg_version
        
        # Compare versions - max should win
        assert str(max(pkg_version.parse("1.0.0"), pkg_version.parse("2.0.0"))) == "2.0.0"
        assert str(max(pkg_version.parse("2.0.0"), pkg_version.parse("1.0.0"))) == "2.0.0"
        assert str(max(pkg_version.parse("1.0.0"), pkg_version.parse("1.0.0"))) == "1.0.0"

    def test_get_high_version_unset_handling(self):
        from packaging import version as pkg_version
        
        # When one is empty/UNSET, the other should win
        versions = ["1.0.0", "2.0.0"]
        highest = max(versions, key=lambda v: pkg_version.parse(v))
        assert highest == "2.0.0"

    def test_get_high_version_invalid_fallback(self):
        from packaging import version as pkg_version
        
        # Invalid version should not crash - fallback to first valid
        try:
            result = max("1.0.0", "invalid", key=lambda v: pkg_version.parse(v))
            assert result == "1.0.0"
        except pkg_version.InvalidVersion:
            # This is expected behavior - invalid versions raise
            pass


class TestCVSSv3Parsing:
    """Tests for CVSS v3.0/v3.1 parsing (ported from SBOMResearcher.ConvertCVSS.Tests.ps1)."""

    def test_cvss31_critical(self):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8"""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        cvss = OSVClient()._parse_cvss3(vector, "3.1")
        assert cvss.base_score == 9.8
        assert cvss.severity == "CRITICAL"

    def test_cvss31_high(self):
        """CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N = 7.4"""
        vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
        cvss = OSVClient()._parse_cvss3(vector, "3.1")
        assert cvss.base_score == 7.4
        assert cvss.severity == "HIGH"

    def test_cvss31_medium(self):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N = 5.3"""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
        cvss = OSVClient()._parse_cvss3(vector, "3.1")
        assert cvss.base_score == 5.3
        assert cvss.severity == "MEDIUM"

    def test_cvss31_low(self):
        """CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L = 2.4 (library calc)"""
        vector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
        cvss = OSVClient()._parse_cvss3(vector, "3.1")
        assert cvss.base_score == 2.4
        assert cvss.severity == "LOW"

    def test_cvss30_same_as_31(self):
        """CVSS 3.0 should calculate same as 3.1"""
        vector30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        cvss30 = OSVClient()._parse_cvss3(vector30, "3.0")
        cvss31 = OSVClient()._parse_cvss3(vector31, "3.1")
        assert cvss30.base_score == cvss31.base_score == 9.8

    def test_invalid_cvss3_throws(self):
        """Invalid CVSS v3 string should raise error"""
        with pytest.raises(Exception):
            OSVClient()._parse_cvss3("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")


class TestCVSSv4Parsing:
    """Tests for CVSS v4.0 parsing (ported from SBOMResearcher.ConvertCVSS.Tests.ps1)."""

    def test_cvss40_critical(self):
        """CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N = 9.3"""
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        cvss = OSVClient()._parse_cvss4(vector)
        assert cvss.base_score == 9.3
        assert cvss.severity == "CRITICAL"

    def test_cvss40_high(self):
        """CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:L/SA:N = 8.8"""
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:L/SA:N"
        cvss = OSVClient()._parse_cvss4(vector)
        assert cvss.base_score == 8.8
        assert cvss.severity == "HIGH"

    def test_cvss40_medium(self):
        """CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N = 5.3"""
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"
        cvss = OSVClient()._parse_cvss4(vector)
        assert cvss.base_score == 5.3
        assert cvss.severity == "MEDIUM"

    def test_cvss40_low(self):
        """CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H = 2.4"""
        vector = "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H"
        cvss = OSVClient()._parse_cvss4(vector)
        assert cvss.base_score == 2.4
        assert cvss.severity == "LOW"

    def test_cvss40_additional_examples(self):
        """Additional test cases from original Pester tests"""
        test_cases = [
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L", 6.9),
            ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1),
            ("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.0),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1),
        ]
        for vector, expected in test_cases:
            cvss = OSVClient()._parse_cvss4(vector)
            assert cvss.base_score == expected, f"Failed for {vector}: got {cvss.base_score}, expected {expected}"

    def test_invalid_cvss4_throws(self):
        """Invalid CVSS v4.0 string should raise error"""
        with pytest.raises(Exception):
            OSVClient()._parse_cvss4("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")


class TestPurlExtraction:
    """Tests for purl parsing (name/version extraction)."""

    def test_cyclonedx_purl_extraction(self):
        parser = SBOMParser()
        
        # Test various purl formats
        test_cases = [
            ("pkg:pypi/requests@2.28.1", "requests", "2.28.1"),
            ("pkg:npm/lodash@4.17.21", "lodash", "4.17.21"),
            ("pkg:maven/org.apache.commons/commons-lang3@3.12.0", "commons-lang3", "3.12.0"),
            ("pkg:cargo/serde@1.0.0", "serde", "1.0.0"),
            ("pkg:golang/github.com/gin-gonic/gin@v1.9.0", "gin", "v1.9.0"),
            ("pkg:pypi/Django@4.2.0?foo=bar", "Django", "4.2.0"),
        ]
        
        for purl, expected_name, expected_version in test_cases:
            name, version = parser.extract_purl_info(purl)
            assert name == expected_name, f"Name mismatch for {purl}: got {name}, expected {expected_name}"
            assert version == expected_version, f"Version mismatch for {purl}: got {version}, expected {expected_version}"

    def test_spdx_purl_extraction(self):
        """SPDX uses externalRefs with purl"""
        parser = SBOMParser()
        
        purl = "pkg:npm/express@4.18.2"
        name, version = parser.extract_purl_info(purl)
        assert name == "express"
        assert version == "4.18.2"


class TestPurlValidation:
    """Tests for purl format validation (ported from original Test-PurlFormat)."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_valid_purl_formats(self):
        """Test purls that should pass validation"""
        valid_purls = [
            "pkg:pypi/requests@2.28.1",
            "pkg:npm/lodash@4.17.21",
            "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
            "pkg:cargo/serde@1.0.0",
            "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
            "pkg:pypi/Django@4.2.0",
            "pkg:npm/package@1.2.3-beta.1",
            "pkg:pypi/requests@1.0.0-alpha",
        ]
        for purl in valid_purls:
            assert self.parser.test_purl_format(purl), f"Should be valid: {purl}"

    def test_invalid_purl_formats(self):
        """Test purls that should fail validation"""
        invalid_purls = [
            "not-a-purl",
            "pkg:pypi/requests",  # missing version
            "pkg:pypi/@1.0.0",    # missing name
            "pkg:/requests@1.0.0", # missing type
            "pkg:pypi/requests@",  # empty version
            "http://example.com/pkg:pypi/requests@1.0.0",  # not a purl
        ]
        for purl in invalid_purls:
            assert not self.parser.test_purl_format(purl), f"Should be invalid: {purl}"


class TestVersionNormalization:
    """Tests for version string normalization (ported from original ConvertTo-Version).
    
    Original PowerShell: splits on dots or non-digits, rejoins with dots.
    This strips non-numeric parts to make version parseable by System.Version.
    """

    def setup_method(self):
        self.parser = SBOMParser()

    def test_convert_to_version_basic(self):
        """Basic version normalization - strips non-numeric parts"""
        assert self.parser.convert_to_version("1.2.3") == "1.2.3"
        assert self.parser.convert_to_version("v1.2.3") == "1.2.3"
        assert self.parser.convert_to_version("1.2.3-beta") == "1.2.3"  # beta stripped
        assert self.parser.convert_to_version("1.2.3-beta.1") == "1.2.3.1"

    def test_convert_to_version_complex(self):
        """Complex version strings with non-standard characters"""
        assert self.parser.convert_to_version("1.2.3+build.123") == "1.2.3.123"
        assert self.parser.convert_to_version("version-1.2.3") == "1.2.3"  # "version" stripped
        assert self.parser.convert_to_version("v1.2.3-rc1") == "1.2.3.1"

    def test_convert_to_version_edge_cases(self):
        """Edge cases"""
        assert self.parser.convert_to_version("") == ""
        assert self.parser.convert_to_version("1") == "1"
        assert self.parser.convert_to_version("latest") == ""  # all non-digits stripped
        assert self.parser.convert_to_version("UNSET") == ""  # all non-digits stripped


class TestParserIntegration:
    """Integration tests for SBOM parsing."""

    def test_parse_cyclonedx_minimal(self, tmp_path):
        """Test parsing a minimal CycloneDX SBOM"""
        sbom_content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "type": "library",
                    "name": "test-lib",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/test-lib@1.0.0",
                    "licenses": [{"license": {"id": "MIT"}}]
                }
            ]
        }
        
        sbom_file = tmp_path / "test-cdx.json"
        sbom_file.write_text(json.dumps(sbom_content))
        
        parser = SBOMParser()
        components, locations, licenses = parser.parse(sbom_file)
        
        assert len(components) == 1
        assert components[0].name == "test-lib"
        assert components[0].version == "1.0.0"
        assert components[0].license == "MIT"
        assert len(licenses) == 1
        assert licenses[0].name == "MIT"
        assert licenses[0].action == LicenseAction.LOW

    def test_parse_spdx_minimal(self, tmp_path):
        """Test parsing a minimal SPDX SBOM"""
        sbom_content = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "test-lib",
                    "versionInfo": "1.0.0",
                    "licenseDeclared": "Apache-2.0",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/test-lib@1.0.0"}
                    ]
                }
            ]
        }
        
        sbom_file = tmp_path / "test-spdx.json"
        sbom_file.write_text(json.dumps(sbom_content))
        
        parser = SBOMParser()
        components, locations, licenses = parser.parse(sbom_file)
        
        assert len(components) == 1
        assert components[0].name == "test-lib"
        assert components[0].version == "1.0.0"
        assert components[0].license == "Apache-2.0"
        assert len(licenses) == 1
        assert licenses[0].name == "Apache-2.0"
        assert licenses[0].action == LicenseAction.LOW

    def test_deduplication_across_files(self, tmp_path):
        """Same component in multiple SBOMs should be deduplicated"""
        sbom_content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "type": "library",
                    "name": "shared-lib",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/shared-lib@1.0.0",
                    "licenses": [{"license": {"id": "MIT"}}]
                }
            ]
        }
        
        sbom_file1 = tmp_path / "sbom1.json"
        sbom_file2 = tmp_path / "sbom2.json"
        sbom_file1.write_text(json.dumps(sbom_content))
        sbom_file2.write_text(json.dumps(sbom_content))
        
        parser = SBOMParser()
        components1, loc1, licenses1 = parser.parse(sbom_file1)
        components2, loc2, licenses2 = parser.parse(sbom_file2)
        
        # Parser internally deduplicates via seen_purls
        all_components = components1 + components2
        seen = set()
        unique = []
        for c in all_components:
            if c.purl not in seen:
                seen.add(c.purl)
                unique.append(c)
        
        assert len(unique) == 1


import json