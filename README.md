# SBOM-Researcher-Python

Cross-platform Python port of [bigdawgsfootball/SBOM-Researcher](https://github.com/bigdawgsfootball/SBOM-Researcher) (PowerShell).

## Purpose

Analyze SBOMs (CycloneDX, SPDX) for vulnerabilities via OSV.dev, calculate CVSS scores (v3.0, v3.1, v4.0), and classify license risk — all on Linux/macOS/Windows.

## Status

**Early development** — porting core logic from PowerShell.

## Original Project

This is a clean-room rewrite of [SBOM-Researcher](https://github.com/bigdawgsfootball/SBOM-Researcher) in Python for cross-platform support. The original is a PowerShell script designed for Windows environments.

## Planned Features

- [ ] Parse CycloneDX and SPDX SBOMs (JSON)
- [ ] Query OSV.dev API for vulnerabilities
- [ ] CVSS v3.0 / v3.1 / v4.0 score calculation
- [ ] License risk classification (Low/Medium/High action)
- [ ] Text + JSON report output
- [ ] CLI with same interface as original
- [ ] CI/CD for Linux, macOS, Windows

## Installation

```bash
# Coming soon
pip install sbom-researcher
```

## Usage

```bash
# Coming soon
sbom-researcher --sbom-path ./sboms --output-dir ./reports --project-name "MyProject" --min-score 7.0
```

## License

MIT — same as original.