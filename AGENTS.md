# AGENTS.md — SBOM-Researcher-Python

## Project Overview
Cross-platform Python port of [bigdawgsfootball/SBOM-Researcher](https://github.com/bigdawgsfootball/SBOM-Researcher) (PowerShell → Python for Linux/macOS/Windows support).

**Core Requirement**: Exact feature parity with the original PowerShell script. The Python port must function identically to the original but run on Linux/macOS/Windows.

> **Note for AI agents**: Update this file (AGENTS.md) as you make changes to the codebase. Keep the Implementation Status table, test counts, and feature status current.

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

**Note**: `cvss` library >=3.6 supports CVSS v3.x and v4.0 score calculation. All original test vectors validated against FIRST.org calculator.

### Architecture
```
src/sbom_researcher/
├── models.py       # Dataclasses: Component, Vulnerability, Report, CVSSBreakdown, LicenseInfo
├── parser.py       # CycloneDX/SPDX JSON parsing + license classification (Low/Medium/High/Unmapped)
├── osv_client.py   # OSV.dev API client + CVSS v3/v4 parsing
├── reporter.py     # Text + JSON report generation (vulns, locations, licenses)
├── cli.py          # Click CLI matching original PowerShell interface
└── __init__.py

src/osv_service/    # Intranet mirror of api.osv.dev (FastAPI) + offline ingestion
├── models.py       # Pydantic request/response models (osv_service_v1.swagger.json)
├── store.py        # Filesystem store mirroring GCS layout <ECOSYSTEM>/<ID>.json
├── matcher.py      # OSV query matching engine (package/version/commit, ranges, pagination)
├── downloader.py   # GCS JSON+CSV sync, incremental by modified_id.csv, DMZ bundle/import
├── app.py          # FastAPI app: /v1/query, /v1/querybatch, /v1/vulns/{id}
├── cli.py          # osv-service CLI: serve / download / bundle / import-bundle
└── __init__.py
```

> **OSV Service (intranet mirror)**: `osv_service` is an API-identical, self-hosted
> copy of `api.osv.dev` for air-gapped networks. It serves the three production
> endpoints (`/v1/query`, `/v1/querybatch`, `/v1/vulns/{id}`) and never implements
> the experimental endpoints. Data is ingested from OSV's GCS exports using the
> per-record JSON files and the `modified_id.csv` change feed. The `all.zip` download
> is not used as the ingestion source.
>
> **Two deployment modes**:
> - **DMZ copy** (`OSV_SYNC_ENABLED=1`, default): `osv-service download [--loop]`
>   pulls new/updated records from GCS over HTTPS, then `osv-service bundle` packages
>   them (JSON files + `manifest.csv`) into a dated `osv_transport/bundle_<ts>/` folder
>   that a human carries across the air gap.
> - **Intranet copy** (`OSV_SYNC_ENABLED=0`): never touches GCS; `osv-service
>   import-bundle --path <bundle>` ingests a bundle, then `osv-service serve` answers
>   queries. Intranet DNS points `api.osv.dev` at this host so existing tools (incl.
>   SBOM-Researcher) work unchanged.
>
> Storage is filesystem (`<OSV_DATA_DIR>/<ECOSYSTEM>/<ID>.json`) for easy copying; a
> SQL Server/Postgres backend can be dropped in later behind the same `VulnStore`
> interface used by `matcher.py`.

### Implementation Status (vs. Original PowerShell)

| Feature | Status | Notes |
|---------|--------|-------|
| CycloneDX JSON parsing | ✅ Complete | |
| SPDX JSON parsing | ✅ Complete | |
| OSV.dev API query | ✅ Complete | Includes cargo→crates.io mapping |
| CVSS v3.0/v3.1 calculation | ✅ Complete | Via `cvss` library |
| CVSS v4.0 calculation | ✅ Complete | Via `cvss` library (v3.6+) |
| License classification | ✅ Complete | Identical Low/Med/High/Unmapped lists |
| Text report (`_report.txt`) | ✅ Complete | |
| Vulns JSON (`_vulns.json`) | ✅ Complete | |
| Locations JSON (`_locs.json`) | ✅ Complete | |
| License JSON (`_license.json`) | ✅ Complete | With `--print-licenses` |
| CLI interface (6 params) | ✅ Complete | Matches original exactly |
| Purl format validation | ✅ Complete | Ported `Test-PurlFormat` regex validation |
| Non-standard version handling | ✅ Complete | Ported `ConvertTo-Version` fallback for version comparison |

### License Classification (ported from original)
- **Low Action**: MIT, Apache-2.0, BSD, ISC, Unlicense, etc. (permissive)
- **Medium Action**: EPL, MPL, CDDL, Artistic, Python-2.0, etc. (weak copyleft)
- **High Action**: GPL, LGPL, AGPL, CC-BY-SA, etc. (strong copyleft)
- **Unmapped**: Unknown SPDX IDs

*Lists are identical to the original PowerShell script.*

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

### Hash-Pinned Requirements (CRITICAL — easy to get wrong)
Scorecard's **Pinned-Dependencies** check fails (`pipCommand not pinned by hash`,
`containerImage not pinned by hash`) unless every `pip install` uses
`--require-hashes -r <file>` against a hash-pinned lockfile, and Docker `FROM` images
are pinned by `@sha256:` digest.

> **Generate the lockfiles on Linux, not Windows.**
> `pip`/`uv` hashes are computed per **wheel file**, and wheel hashes differ by OS,
> architecture, and Python version. If a lockfile is generated on a Windows host (or a
> different Python version than CI), the hashes will NOT match the `ubuntu-latest` /
> ClusterFuzzLite runners, and `pip install --require-hashes` will fail in CI even though
> the workflow "looks" correct. Several prior attempts committed Windows-generated hashes
> that silently broke the Linux CI.

Rules of thumb:
- Lockfiles live in `.github/requirements/` (`*.in` sources + `*.txt` lockfiles).
- Generate with `uv pip compile --generate-hashes --python-version <V>`:
  - security.yml jobs (`ubuntu-latest`, `setup-python: '3.10'`) → `--python-version 3.10`
  - ClusterFuzzLite (`gcr.io/oss-fuzz-base/base-builder-python`, Python 3.11) → `--python-version 3.11`
- Run the generation inside **WSL** (`wsl bash -lc '...'`), a Linux container, or a
  Linux CI step — never a native Windows shell.
- Local/editable installs (`pip install -e .`) **cannot** be hash-pinned. Make the
  package importable via `PYTHONPATH=<repo>/src` instead (pyinstaller bundles it at
  build time; tests import it directly). Never add a bare `pip install` to a workflow or
  `build.sh` without `--require-hashes -r <hash-pinned file>`.
- After editing a `*.in`, regenerate the matching `*.txt` and commit both.

## Testing
- Unit tests in `tests/` (68 tests passing)
  - `tests/test_models.py` - 4 tests for data models
  - `tests/test_parser.py` - 33 tests for parser, CVSS v3/v4, license classification, version handling, purl extraction, purl validation, version normalization
  - `tests/test_osv_client.py` - 14 tests for OSV client, CVSS breakdown, vulnerability parsing
  - `tests/test_osv_service.py` - 14 tests for the OSV mirror API parity + SBOM-Researcher `OSVClient` integration
  - `tests/test_downloader.py` - 2 tests for GCS sync (incremental) + DMZ bundle/import transfer
  - `tests/test_smoke_realdata.py` - 1 real-data parity test (marker `smoke`, network-guarded, fetches a single real record)
- Run: `pytest tests/ -v`
- Coverage: `pytest tests/ --cov=src`

**Tests are a superset of the original PowerShell Pester tests** — all original test cases ported plus additional tests for new Python-specific functionality (purl validation, version normalization fallback).

All tests ported from original PowerShell Pester tests:
- SBOMResearcher.ConvertCVSS.Tests.ps1 → test_parser.py (CVSS v3/v4)
- SBOMResearcher.License.Tests.ps1 → test_parser.py (License classification)
- SBOMResearcher.Version.Tests.ps1 → test_parser.py (Version handling, purl extraction)

## Quality Gates
All must pass before merge:
- `ruff check src/` — linting
- `mypy src/` — type checking (strict mode)
- `pytest tests/` — unit tests

## Branch Management
- **Commit locally, push only on instruction:** Make local commits as you work, but
  DO NOT push to the remote until explicitly told. When instructed to push: push the
  current branch, open a PR, then immediately start a fresh branch off `main`
  (`git switch -c <new> origin/main`) so no further commits land on the just-pushed
  branch. This yields exactly one PR per push and prevents the merge-loop (where a
  branch receives commits after its PR is opened/merged and they get silently
  orphaned by a squash merge).
- Stale branches (e.g., `gh-pages`) should be deleted after merge to `main`
- All changes must go through PRs against `main` (branch protection enabled)
- **Repo setting `delete_branch_on_merge` is ENABLED** — GitHub auto-deletes the
  head branch when a PR is merged. Do not recreate or push to it afterward.
- **CRITICAL — one branch per PR, and never push to a merged branch:**
  - As soon as a PR is merged, start any follow-up work on a **brand-new branch**
    off `main`. Never commit/push more to the branch whose PR was just merged
    (that recreates the branch, reopens/re-targets the PR, and orphans the commits).
  - Squash merges only capture the commits present at merge time. Commits pushed
    to the branch *after* the merge point are NOT included and are effectively lost
    (git does not mark a squash-merged branch as merged). This is how fixes
    silently fail to land — always open a fresh PR for anything missed.
  - After a merge, also delete the local branch (`git branch -D <name>`) so neither
    the local nor remote copy lingers.

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