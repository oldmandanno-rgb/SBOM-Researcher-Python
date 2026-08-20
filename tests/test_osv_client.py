"""Tests for OSV client."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from sbom_researcher.osv_client import OSVClient
from sbom_researcher.models import Component, Vulnerability, CVSSBreakdown


class TestOSVClient:
    """Tests for OSV client functionality."""

    def test_query_transforms_cargo_to_crates_io(self):
        """OSV uses crates.io not cargo for Rust packages"""
        with patch('sbom_researcher.osv_client.httpx.Client') as mock_client:
            mock_response = Mock()
            mock_response.json.return_value = {"vulns": []}
            mock_response.raise_for_status = Mock()
            mock_client.return_value.post.return_value = mock_response
            
            client = OSVClient()
            result = client.query("pkg:cargo/serde@1.0.0")
            
            # Verify the purl was transformed
            call_args = mock_client.return_value.post.call_args
            assert call_args is not None
            body = call_args[1]['json']
            assert body['package']['purl'] == "pkg:crates.io/serde@1.0.0"

    def test_query_passes_other_purls_unchanged(self):
        """Non-cargo purls should pass through unchanged"""
        with patch('sbom_researcher.osv_client.httpx.Client') as mock_client:
            mock_response = Mock()
            mock_response.json.return_value = {"vulns": []}
            mock_response.raise_for_status = Mock()
            mock_client.return_value.post.return_value = mock_response
            
            client = OSVClient()
            client.query("pkg:pypi/requests@2.28.1")
            
            call_args = mock_client.return_value.post.call_args
            body = call_args[1]['json']
            assert body['package']['purl'] == "pkg:pypi/requests@2.28.1"

    def test_parse_vulnerabilities_empty_response(self):
        """Empty OSV response should return empty list"""
        client = OSVClient()
        component = Component(name="test", version="1.0.0", purl="pkg:pypi/test@1.0.0")
        result = client.parse_vulnerabilities(component, {"vulns": []})
        assert result == []

    def test_parse_vulnerabilities_filters_by_min_score(self):
        """Vulnerabilities below min_score should be filtered out"""
        client = OSVClient()
        component = Component(name="test", version="1.0.0", purl="pkg:pypi/test@1.0.0")
        
        osv_response = {
            "vulns": [
                {"id": "CVE-2023-001", "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},  # 9.8
                {"id": "CVE-2023-002", "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}]},  # ~5.3
            ]
        }
        
        # Only high severity
        result = client.parse_vulnerabilities(component, osv_response, min_score=7.0)
        assert len(result) == 1
        assert result[0].id == "CVE-2023-001"
        
        # All
        result = client.parse_vulnerabilities(component, osv_response, min_score=0.0)
        assert len(result) == 2

    def test_parse_vulnerabilities_includes_unscored(self):
        """Vulnerabilities without CVSS score should be included (unassessed)"""
        client = OSVClient()
        component = Component(name="test", version="1.0.0", purl="pkg:pypi/test@1.0.0")
        
        osv_response = {
            "vulns": [
                {"id": "CVE-2023-001"},  # No severity field
            ]
        }
        
        result = client.parse_vulnerabilities(component, osv_response, min_score=7.0)
        assert len(result) == 1
        assert result[0].id == "CVE-2023-001"
        assert result[0].score is None

    def test_extract_fixed_version_from_ranges(self):
        """Should extract highest fixed version from affected ranges"""
        client = OSVClient()
        
        vuln_data = {
            "affected": [
                {
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]},
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]},
                        {"type": "GIT", "events": [{"fixed": "abc123"}]}  # Should be ignored
                    ]
                }
            ]
        }
        
        fixed = client._extract_fixed_version(vuln_data)
        assert fixed == "1.2.4"  # Highest version

    def test_extract_fixed_version_no_fixed(self):
        """Should return None when no fixed version found"""
        client = OSVClient()
        
        vuln_data = {
            "affected": [
                {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}
            ]
        }
        
        fixed = client._extract_fixed_version(vuln_data)
        assert fixed is None

    def test_parse_single_vulnerability_full(self):
        """Parse a complete vulnerability entry"""
        client = OSVClient()
        
        vuln_data = {
            "id": "CVE-2023-12345",
            "summary": "Test vulnerability",
            "details": "Detailed description",
            "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [
                {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}
            ]
        }
        
        vuln = client._parse_single(vuln_data)
        
        assert vuln is not None
        assert vuln.id == "CVE-2023-12345"
        assert vuln.summary == "Test vulnerability"
        assert vuln.details == "Detailed description"
        assert vuln.fixed_version == "2.0.0"
        assert vuln.score == 9.8
        assert vuln.severity == "CRITICAL"
        assert vuln.cvss is not None
        assert vuln.cvss.version == "3.1"

    def test_parse_single_vulnerability_cvss4(self):
        """Parse vulnerability with CVSS v4.0"""
        client = OSVClient()
        
        vuln_data = {
            "id": "CVE-2023-12345",
            "severity": [{"score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
            "affected": []
        }
        
        vuln = client._parse_single(vuln_data)
        
        assert vuln is not None
        assert vuln.score == 9.3
        assert vuln.cvss.version == "4.0"

    def test_severity_from_score(self):
        """Test severity classification from score"""
        client = OSVClient()
        
        assert client._severity_from_score(9.5) == "CRITICAL"
        assert client._severity_from_score(9.0) == "CRITICAL"
        assert client._severity_from_score(7.5) == "HIGH"
        assert client._severity_from_score(7.0) == "HIGH"
        assert client._severity_from_score(5.0) == "MEDIUM"
        assert client._severity_from_score(4.0) == "MEDIUM"
        assert client._severity_from_score(2.0) == "LOW"
        assert client._severity_from_score(0.1) == "LOW"
        assert client._severity_from_score(0.0) == "NONE"

    def test_context_manager(self):
        """Test OSVClient as context manager"""
        with OSVClient() as client:
            assert client.client is not None
        # Should not raise


class TestCVSSBreakdown:
    """Tests for CVSS breakdown data model."""

    def test_cvss3_breakdown_fields(self):
        """CVSS v3 breakdown should have all expected fields"""
        cvss = CVSSBreakdown(
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            version="3.1",
            base_score=9.8,
            severity="CRITICAL",
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
            score_url="https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        
        assert cvss.attack_vector == "N"
        assert cvss.scope == "U"
        assert cvss.version == "3.1"

    def test_cvss4_breakdown_fields(self):
        """CVSS v4 breakdown should have v4-specific fields"""
        cvss = CVSSBreakdown(
            vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            version="4.0",
            base_score=9.3,
            severity="CRITICAL",
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope=None,  # v4 uses different metrics
            confidentiality="H",
            integrity="H",
            availability="H",
            score_url="https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        )
        
        assert cvss.version == "4.0"
        assert cvss.scope is None