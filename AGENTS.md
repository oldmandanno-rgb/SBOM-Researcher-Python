# AGENTS.md — SBOM-Researcher-Python

## Project Overview
Cross-platform Python port of [bigdawgsfootball/SBOM-Researcher](https://github.com/bigdawgsfootball/SBOM-Researcher) (PowerShell → Python for Linux/macOS/Windows support).

## Key Decisions

### Repository Strategy
- **New repo** (not fork): `oldmandanno-rgb/SBOM-Researcher-Python`
- **Link back**: README prominently references original with "Port of..." notice
- **No submodule**: Simple README link is sufficient for traceability
- **Branch protection**: Enabled on `main`/`master` — all changes via PR

### Technology Choices
| Component | Library | Version | Rationale |
|-----------|---------|---------|-----------|
| SBOM parsing (CycloneDX) | `cyclonedx-python-lib` | >=9.0 | Native Python, active maintenance |
| SBOM parsing (SPDX) | `spdx-tools` | >=0.8 | Official SPDX Python tooling |
| HTTP client | `httpx` | >=0.25 | Async-capable, modern API |
| Version comparison | `packaging` | >=23 | PEP 440 compliant |
| CVSS calculation | `cvss` | >=3.6 | Only library supporting v3.x |
| CLI framework | `click` | >=8.1 | Simple, composable |
| Rich output | `rich` | >=13.0 | Progress bars, tables, formatting |
| Data models | `pydantic` | >=2.0 | Validation, serialization |
| Type checking | `mypy` | >=1.5 | Strict mode enabled |
| Linting | `ruff` | >=0.1 | Fast, comprehensive |

**Note**: `cvss` library only supports v3.x; CVSS v4.0 parsing is partial (vector breakdown only, no score calc).

### Architecture
```
src/sbom_researcher/
├── models.py       # Dataclasses: Component, Vulnerability, Report, CVSSBreakdown, LicenseInfo
├── parser.py       # CycloneDX/SPDX JSON parsing + license classification (Low/Medium/High/Unmapped)
├── osv_client.py   # OSV.dev API client + CVSS v3/v4 parsing
├── reporter.py     # Text + JSON report generation (vulns, locations, licenses)
├── cli.py          # Click CLI matching original PowerShell interface
└── __init__.py
```

### License Classification (ported from original)
- **Low Action**: MIT, Apache-2.0, BSD, ISC, Unlicense, etc. (permissive)
- **Medium Action**: EPL, MPL, CDDL, Artistic, Python-2.0, etc. (weak copyleft)
- **High Action**: GPL, LGPL, AGPL, CC-BY-SA, etc. (strong copyleft)
- **Unmapped**: Unknown SPDX IDs

### CLI Interface (matches original)
```bash
sbom-researcher --sbom-path PATH --output-dir PATH --project-name NAME \
  [--min-score FLOAT] [--list-all] [--print-licenses]
```

### Outputs
- `{project}_report.txt` — Human-readable text report
- `{project}_vulns.json` — Vulnerabilities with CVSS details
- `{project}_locs.json` — Component → SBOM file mapping
- `{project}_license.json` — License classification (if `--print-licenses`)

## Security Workflow (`.github/workflows/security.yml`)

### Enabled Scanners
| Job | Tool | Purpose |
|-----|------|---------|
| `codeql` | GitHub CodeQL | SAST for Python |
| `dependabot` | pip-audit | Dependency vulnerability scan |
| `bandit` | Bandit | Python security anti-patterns |
| `trivy` | Trivy | FS vulns, secrets, misconfigs |
| `semgrep` | Semgrep | SAST + secrets (security-audit, python, secrets rulesets) |
| `scorecard` | OpenSSF Scorecard | Supply chain security posture |
| `tests` | pytest | Unit tests + coverage |

### Fixes Applied
1. **Permissions**: Added `security-events: write` to SARIF-uploading jobs (Trivy, Semgrep, Scorecard)
2. **pip-audit**: `|| true` to not fail on unpinned pip vulnerabilities
3. **Scorecard**: `repo_token: ${{ secrets.GITHUB_TOKEN }}` + `exclude: Branch-Protection` (until branch protection configured)
4. **Semgrep**: Pinned to `@v1` (stable) instead of `@main`
5. **Branch protection**: Now enabled — all changes via PR

## Testing
- Unit tests in `tests/test_models.py` (4 tests passing)
- Run: `pytest tests/ -v`
- Coverage: `--cov=src/sbom_researcher`

## Quality Gates
All must pass before merge:
- `ruff check src/` — linting
- `mypy src/` — type checking (strict mode)
- `pytest tests/` — unit tests

## Development Setup
```bash
git clone https://github.com/oldmandanno-rgb/SBOM-Researcher-Python.git
cd SBOM-Researcher-Python
pip install -e .[dev]
pre-commit install  # optional
```

## Future Work
- [ ] Full CVSS v4.0 score calculation (wait for `cvss` lib update or implement)
- [ ] Integration tests with sample SBOMs
- [ ] GitHub Release workflow
- [ ] PyPI publishing workflow
- [ ] Docker image build
- [ ] Performance optimization for large SBOM sets
- [ ] SPDX tag-value format support (currently JSON only)

## Original Project Reference
- Repo: https://github.com/bigdawgsfootball/SBOM-Researcher
- Language: PowerShell (Windows-only)
- Security: PSScriptAnalyzer, Scorecard, Dependency Review, Dependabot, Pester tests
- Our port adds: CodeQL, Bandit, Trivy, Semgrep, pip-audit, mypy, ruff