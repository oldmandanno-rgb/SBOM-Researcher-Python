# SBOM-Researcher-Python

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/oldmandanno-rgb/SBOM-Researcher-Python/badge)](https://scorecard.dev/viewer/?uri=github.com/oldmandanno-rgb/SBOM-Researcher-Python)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/oldmandanno-rgb/SBOM-Researcher-Python)
[![CodeQL](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/workflows/CodeQL/badge.svg)](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/actions/workflows/security.yml)
[![Coverage](https://codecov.io/gh/oldmandanno-rgb/SBOM-Researcher-Python/branch/main/graph/badge.svg)](https://codecov.io/gh/oldmandanno-rgb/SBOM-Researcher-Python)
[![Dependabot](https://badgen.net/github/dependabot/oldmandanno-rgb/SBOM-Researcher-Python)](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/network/updates)

Cross-platform Python port of [bigdawgsfootball/SBOM-Researcher](https://github.com/bigdawgsfootball/SBOM-Researcher) (PowerShell).

## Purpose

Analyze SBOMs (CycloneDX, SPDX) for vulnerabilities via OSV.dev, calculate CVSS scores (v3.0, v3.1, v4.0), and classify license risk — all on Linux/macOS/Windows.

## Status

**Feature complete** — core functionality implemented with exact feature parity to original PowerShell script. 51 unit tests passing.

## Original Project

This is a clean-room rewrite of [SBOM-Researcher](https://github.com/bigdawgsfootball/SBOM-Researcher) in Python for cross-platform support. The original is a PowerShell script designed for Windows environments.

## Features

- ✅ Parse CycloneDX and SPDX SBOMs (JSON)
- ✅ Query OSV.dev API for vulnerabilities (with cargo→crates.io mapping)
- ✅ CVSS v3.0 / v3.1 score calculation (via `cvss` library)
- ✅ CVSS v4.0 score calculation (validated against FIRST.org calculator)
- ✅ License risk classification (Low/Medium/High/Unmapped action)
- ✅ Text + JSON report output (4 report files)
- ✅ CLI with identical interface to original (6 parameters)
- ✅ CI/CD for Linux, macOS, Windows

## Installation

```bash
git clone https://github.com/oldmandanno-rgb/SBOM-Researcher-Python.git
cd SBOM-Researcher-Python
pip install -e .
```

## Usage

```bash
sbom-researcher --sbom-path ./sboms --output-dir ./reports --project-name "MyProject" --min-score 7.0
```

### Options
| Option | Short | Description |
|--------|-------|-------------|
| `--sbom-path` | `-s` | Path to SBOM file or directory (required) |
| `--output-dir` | `-o` | Output directory for reports (required) |
| `--project-name` | `-p` | Project name for report files (required) |
| `--min-score` | `-m` | Minimum CVSS score to report (0-10, default: 0.0) |
| `--list-all` | `-a` | List all components even without vulnerabilities |
| `--print-licenses` | `-l` | Include license classification in report |

## Outputs

- `{project}_report.txt` — Human-readable text report
- `{project}_vulns.json` — Vulnerabilities with CVSS details
- `{project}_locs.json` — Component → SBOM file mapping
- `{project}_license.json` — License classification (if `--print-licenses`)

## Development

```bash
pip install -e .[dev]
pytest tests/ -v
ruff check src/
mypy src/
```

## License

MIT — same as original.