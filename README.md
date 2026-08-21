# SBOM-Researcher-Python

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/oldmandanno-rgb/SBOM-Researcher-Python/badge)](https://scorecard.dev/viewer/?uri=github.com/oldmandanno-rgb/SBOM-Researcher-Python)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/oldmandanno-rgb/SBOM-Researcher-Python)
[![CodeQL](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/workflows/Security%20Scans/badge.svg)](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/actions/workflows/security.yml)
[![Coverage](https://codecov.io/gh/oldmandanno-rgb/SBOM-Researcher-Python/branch/main/graph/badge.svg)](https://codecov.io/gh/oldmandanno-rgb/SBOM-Researcher-Python)
[![Dependabot](https://badgen.net/github/dependabot/oldmandanno-rgb/SBOM-Researcher-Python)](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/network/updates)
[![Semgrep](https://img.shields.io/endpoint?url=https://oldmandanno-rgb.github.io/SBOM-Researcher-Python/semgrep.json)](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/actions/workflows/security.yml)
[![Bandit](https://img.shields.io/endpoint?url=https://oldmandanno-rgb.github.io/SBOM-Researcher-Python/bandit.json)](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/actions/workflows/security.yml)
[![Trivy](https://img.shields.io/endpoint?url=https://oldmandanno-rgb.github.io/SBOM-Researcher-Python/trivy.json)](https://github.com/oldmandanno-rgb/SBOM-Researcher-Python/actions/workflows/security.yml)

This repository contains two related tools:

1. **SBOM-Researcher** — a cross-platform Python port of
   [bigdawgsfootball/SBOM-Researcher](https://github.com/bigdawgsfootball/SBOM-Researcher)
   (PowerShell). It parses CycloneDX / SPDX SBOMs and queries a vulnerability
   source for each component, then produces human-readable and JSON reports
   with CVSS scoring (v3.0 / v3.1 / v4.0) and license-risk classification.
   It is provided here as a **custom example client** for the service below.
2. **osv_service** — a self-hosted, API-identical mirror of
   [`api.osv.dev`](https://api.osv.dev) for air-gapped / intranet networks.
   Because the API is byte-for-byte compatible, **any tool that already speaks
   OSV.dev works unchanged** — including commercial scanners and SBOM tools —
   simply by pointing DNS at the mirror.

## Purpose

Organizations that cannot reach the public internet still need vulnerability
data. `osv_service` is an intranet copy of OSV.dev that:

* serves the same three production endpoints (`/v1/query`, `/v1/querybatch`,
  `/v1/vulns/{id}`) with identical request/response shapes,
* ingests data from OSV's own GCS exports (the stable JSON records + the
  `modified_id.csv` change feed — the unstable `all.zip` is deliberately **not**
  used), and
* provides a human-mediated DMZ → intranet transfer path for air-gapped
  environments.

`SBOM-Researcher` is the reference client: it demonstrates how to query the
service and can be pointed at the mirror during development with zero code
changes.

## Repository layout

```
src/
├── sbom_researcher/   # Example OSV client + SBOM parser + reporter (CLI: sbom-researcher)
│   ├── models.py      # Component / Vulnerability / CVSSBreakdown / LicenseInfo
│   ├── parser.py      # CycloneDX + SPDX parsing, license classification
│   ├── osv_client.py  # OSV API client (supports OSV_API_BASE_URL override)
│   ├── reporter.py    # Text + JSON report generation
│   └── cli.py         # Click CLI (6 params, identical to original)
└── osv_service/       # Intranet OSV mirror (CLI: osv-service)
    ├── models.py      # Pydantic request/response models (osv_service_v1.swagger.json)
    ├── store.py       # Filesystem store mirroring <ECOSYSTEM>/<ID>.json
    ├── matcher.py     # OSV query engine (package/version/commit, ranges, pagination)
    ├── downloader.py  # GCS JSON+CSV sync, incremental; DMZ bundle / import-bundle
    ├── app.py         # FastAPI: /v1/query, /v1/querybatch, /v1/vulns/{id}
    └── cli.py         # serve / download / bundle / import-bundle
```

## Installation

```bash
git clone https://github.com/oldmandanno-rgb/SBOM-Researcher-Python.git
cd SBOM-Researcher-Python
pip install -e .
```

This installs both `sbom-researcher` and `osv-service` console scripts, plus
the `fastapi` / `uvicorn` dependencies the mirror needs.

---

## Setting up the osv_service mirror

### Two deployment modes

| Mode | Where | Talks to GCS? | Commands |
|------|-------|--------------|----------|
| **DMZ copy** | Reaches the internet | Yes | `osv-service download [--loop]` then `osv-service bundle` |
| **Intranet copy** | Air-gapped | **No** (`OSV_SYNC_ENABLED=0`) | `osv-service import-bundle --path <bundle>` then `osv-service serve` |

The DMZ copy syncs new/updated records on a schedule (humans move data across
the gap whenever convenient — the sync is incremental and idempotent). The
intranet copy never contacts GCS; it only ingests bundles that a human carries
over, then serves queries.

### 1. DMZ copy — populate and export

```bash
# One-shot pull of everything new, then package it for transfer
osv-service download --data-dir ./osv_data --outbox ./osv_outbox
osv-service bundle   --data-dir ./osv_data --outbox ./osv_outbox --transport ./osv_transport

# Or run it on a loop so changes accumulate until someone collects them.
# --interval is in SECONDS; the default is 86400 (1 day). Set it anywhere
# between sync passes, e.g. every 6 hours (21600) or every 2 days (172800).
osv-service download --data-dir ./osv_data --outbox ./osv_outbox --loop --interval 86400
```

> **Setting the sync interval:** the `--interval` flag on `osv-service download`
> controls the gap between sync passes and is expressed in **seconds** (it is
> passed straight to `time.sleep`). The built-in default is `86400` (1 day).
> Override it per run — e.g. `--interval 21600` for 6 hours or `--interval 172800`
> for 2 days. It only applies to the DMZ copy; the intranet copy never polls.

`download` streams `modified_id.csv` (newest-first) and fetches only records
newer than the last run, writing each as `<data-dir>/<ECOSYSTEM>/<ID>.json` and
appending a row to `<outbox>/pending.csv`. `bundle` snapshots those JSON files
plus a `manifest.csv` into a dated, self-contained folder
`<transport>/bundle_<timestamp>/` for the human to carry across.

### 2. Intranet copy — import and serve

```bash
# On the intranet host (never touches GCS)
export OSV_SYNC_ENABLED=0
osv-service import-bundle --data-dir ./osv_data --path ./osv_transport/bundle_20260820T000000Z
osv-service serve --data-dir ./osv_data --host 0.0.0.0 --port 8000
```

### 3. Point clients at the mirror

* **Production (any OSV-speaking tool):** configure intranet DNS so
  `api.osv.dev` resolves to the intranet mirror host. No tool changes required —
  commercial scanners, `govulncheck`, dependency-check, SBOM-Researcher, etc.
  all continue to work.
* **Local development / testing:** set `OSV_API_BASE_URL` to redirect just the
  `SBOM-Researcher` client without touching DNS:

  ```bash
  export OSV_API_BASE_URL="http://127.0.0.1:8000/v1/query"
  ```

---

## Example: querying the mirror with SBOM-Researcher

With the mirror serving on `localhost:8000` (from step 2 / 3 above):

```bash
# Tell the example client where the mirror lives (dev only)
export OSV_API_BASE_URL="http://127.0.0.1:8000/v1/query"

# Analyze an SBOM (or a directory of SBOMs) exactly as against public OSV
sbom-researcher \
  --sbom-path ./sboms \
  --output-dir ./reports \
  --project-name "MyProject" \
  --min-score 7.0
```

Output files (written to `--output-dir`):

* `{project}_report.txt` — human-readable report
* `{project}_vulns.json` — vulnerabilities with CVSS details
* `{project}_locs.json` — component → SBOM file mapping
* `{project}_license.json` — license classification (with `--print-licenses`)

In production the `OSV_API_BASE_URL` step is unnecessary — DNS redirection of
`api.osv.dev` makes the same command hit the mirror transparently.

## Direct API usage

The mirror is a drop-in replacement for `api.osv.dev`:

```bash
# Query by package + version
curl -d '{"package":{"name":"jinja2","ecosystem":"PyPI"},"version":"2.4.1"}' \
     http://localhost:8000/v1/query

# Batched query (ids + modified only, order matches input)
curl -d '{"queries":[{"package":{"purl":"pkg:pypi/mlflow@0.4.0"}}]}' \
     http://localhost:8000/v1/querybatch

# Fetch a single record
curl http://localhost:8000/v1/vulns/OSV-2020-744
```

---

## Storage backends (replacing the temporary store with a real database)

The query engine (`matcher.py`) is completely backend-agnostic: it only depends on
the `VulnStore` protocol, declared in `src/osv_service/matcher.py`:

```python
class VulnStore(Protocol):
    def candidate_vulns(self, ecosystem: str, name: str) -> list[dict]: ...
    def get(self, vuln_id: str) -> Optional[dict]: ...
    def all_vulns(self) -> list[dict]: ...
```

`ecosystem` is always passed **already lower-cased** by the matcher, and `name`
is the exact package name. The bundled `JsonFileStore`
(`<data-dir>/<ECOSYSTEM>/<ID>.json`) is the **temporary / development** backend —
it needs no server and is easy to copy, but it is not the production database.

### Production: use SQL Server / Postgres instead

Implement the same three methods against your real database and hand the instance
to `create_app`. For example, with SQLAlchemy:

```python
from sqlalchemy import create_engine, select, text
from osv_service.app import create_app
from osv_service.matcher import VulnStore

class SqlVulnStore:
    """Minimal SQL Server / Postgres-backed VulnStore."""
    def __init__(self, url: str) -> None:
        self.engine = create_engine(url)

    def candidate_vulns(self, ecosystem: str, name: str) -> list[dict]:
        # Index OSV records by (ecosystem_lower, name); return parsed JSON.
        with self.engine.connect() as c:
            rows = c.execute(text(
                "SELECT record FROM vulns "
                "WHERE ecosystem = :eco AND name = :name"
            ), {"eco": ecosystem, "name": name}).all()
        return [r[0] for r in rows]

    def get(self, vuln_id: str):
        with self.engine.connect() as c:
            row = c.execute(text("SELECT record FROM vulns WHERE id = :id"),
                            {"id": vuln_id}).first()
        return row[0] if row else None

    def all_vulns(self) -> list[dict]:
        with self.engine.connect() as c:
            return [r[0] for r in c.execute(text("SELECT record FROM vulns")).all()]

store = SqlVulnStore("mssql+pyodbc://user:pass@server/osv?driver=ODBC+Driver+18+for+SQL+Server")
app = create_app(store)          # hand the real DB to the mirror
# uvicorn this `app`, or:  uvicorn your_module:app
```

The ingestion side (`downloader.py`) still produces the canonical
`<ECOSYSTEM>/<ID>.json` records; for a SQL backend you would load those JSON
files into the `vulns` table (e.g. inside `import-bundle`) instead of writing
them to disk. Everything else — the API, the matcher, pagination, the DMZ/intranet
transfer — is unchanged.

> **Migration at a glance:** replace `JsonFileStore` with your `SqlVulnStore`
> everywhere a store is constructed (the `serve` CLI uses `JsonFileStore` by
> default; for a real DB, build the app with `create_app(your_store)` as shown
> above). No changes to the query API or to any client are required.

## Testing

```bash
pip install -e .[dev]
pytest tests/ -v          # full suite (hermetic)
pytest -m smoke -v        # optional real-data parity test (needs network)
ruff check src/
mypy src/
```

* `test_osv_service.py` — API parity with the public OSV contract + an
  end-to-end check that SBOM-Researcher's `OSVClient` drives the mirror
  unchanged (including the `cargo` → `crates.io` mapping).
* `test_downloader.py` — GCS-style sync (incremental) and DMZ `bundle` →
  intranet `import-bundle` transfer, exercised offline against a mock.
* `test_smoke_realdata.py` (marker `smoke`) — fetches **one** real vulnerability
  record from the OSV GCS export, ingests it, and asserts the local service
  returns it and that the result is a subset of what the live API returns. It is
  intentionally tiny and skips cleanly when offline.

## Notes & limitations

* Version ordering uses `packaging` (PEP 440 / semver) rather than OSV's
  per-ecosystem comparators — faithful for PyPI / npm / Go / Cargo, approximate
  for Debian / Maven.
* Storage is filesystem (`<ECOSYSTEM>/<ID>.json`) for easy copying; a SQL
  Server / Postgres backend can replace `JsonFileStore` behind the same
  `VulnStore` interface used by the matcher.
* The experimental OSV endpoints (`determineversion`, `importfindings`) are not
  implemented — they require data sources not present in the vulnerability dumps.

## Original Project

This is a clean-room rewrite of [SBOM-Researcher](https://github.com/bigdawgsfootball/SBOM-Researcher)
in Python for cross-platform support. The original is a PowerShell script
designed for Windows environments.

## License

MIT — same as original.
