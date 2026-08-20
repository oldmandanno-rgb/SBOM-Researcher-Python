# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in SBOM-Researcher-Python, please report it responsibly.

### How to Report

**Preferred:** Use GitHub's private vulnerability reporting:
1. Go to the [Security Advisories](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/security/advisories) tab
2. Click "Report a vulnerability"
3. Fill in the details

**Alternative:** Email security@oldmandanno-rgb.example.com (PGP key: [link](https://keys.openpgp.org/search?q=security%40oldmandanno-rgb.example.com))

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if known)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix timeline:** Depends on severity (typically 30-90 days)

## Security Features

- **SBOM Analysis:** Parses CycloneDX and SPDX formats for vulnerability detection
- **OSV.dev Integration:** Queries Open Source Vulnerabilities database
- **CVSS Scoring:** Supports CVSS v3.x scoring and vector parsing
- **License Classification:** Categorizes licenses by risk (Low/Medium/High/Unmapped)

## Continuous Security Scanning

This project runs automated security scans on every push/PR:
- CodeQL (SAST)
- pip-audit (dependency vulnerabilities)
- Bandit (Python security anti-patterns)
- Trivy (filesystem vulnerabilities, secrets)
- Semgrep (SAST + secrets detection)
- OpenSSF Scorecard (supply chain posture)

## Disclosure Policy

We follow coordinated vulnerability disclosure. We will:
1. Acknowledge receipt
2. Investigate and validate
3. Develop and test a fix
4. Release patch and advisory
5. Credit reporter (unless anonymous requested)

## Contact

For security questions not related to vulnerability reporting, open a [GitHub Discussion](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/discussions).