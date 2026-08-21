"""Ingestion from OSV.dev GCS exports + DMZ/intranet transfer primitives.

The zip downloads documented by OSV are unstable, so we rely solely on the
JSON records and the ``modified_id.csv`` change feeds (both confirmed stable):

* **Full load / incremental sync** streams ``modified_id.csv`` (reverse
  chronological) and downloads each referenced ``<ECOSYSTEM>/<ID>.json`` over
  HTTPS from ``storage.googleapis.com``. Because the CSV is sorted newest-first,
  we stop as soon as we reach a timestamp we have already seen.
* **DMZ -> intranet transfer** is human-mediated across an air gap. The DMZ copy
  accumulates every newly-synced record into an append-only ``pending.csv``
  manifest. ``create_bundle`` snapshots those JSON files plus the manifest into a
  dated, self-contained folder that a human can carry across the DMZ. The
  intranet copy consumes that folder with ``import_bundle`` and never talks to
  GCS directly (``OSV_SYNC_ENABLED=0``).
"""

from __future__ import annotations

import csv
import io
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import httpx

GCS_BASE = "https://storage.googleapis.com/osv-vulnerabilities"


def fetch_modified_index(
    client: httpx.Client, ecosystem: str | None = None
) -> list[dict[str, str]]:
    """Fetch and parse ``modified_id.csv`` (top-level or per-ecosystem)."""
    path = f"{ecosystem}/modified_id.csv" if ecosystem else "modified_id.csv"
    resp = client.get(f"{GCS_BASE}/{path}")
    resp.raise_for_status()
    rows: list[dict[str, str]] = []
    for row in csv.reader(io.StringIO(resp.text)):
        if not row or len(row) < 2:
            continue
        modified, location = row[0], row[1]
        eco, vuln_id = location.split("/", 1) if "/" in location else ("", location)
        rows.append({"modified": modified, "ecosystem": eco, "id": vuln_id})
    return rows


def download_record(
    client: httpx.Client, ecosystem: str, vuln_id: str
) -> dict[str, Any] | None:
    """Download a single vulnerability JSON record, or None if missing."""
    resp = client.get(f"{GCS_BASE}/{ecosystem}/{vuln_id}.json")
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return cast("dict[str, Any]", resp.json())


def _read_last_seen(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return ""


def sync_once(
    store: Any,
    outbox: Path,
    last_seen_path: Path,
    client: httpx.Client,
    ecosystem: str | None = None,
) -> int:
    """Pull new/updated records from GCS into ``store`` + the DMZ outbox.

    Returns the number of records downloaded. ``modified_id.csv`` is reverse
    chronological, so we stop at the first row already <= ``last_seen``.
    """
    rows = fetch_modified_index(client, ecosystem)
    last_seen = _read_last_seen(last_seen_path)
    pending = outbox / "pending.csv"
    pending_lines: list[tuple[str, str, str, str]] = []
    newest = last_seen
    added = 0

    for row in rows:
        if last_seen and row["modified"] <= last_seen:
            break
        rec = download_record(client, row["ecosystem"], row["id"])
        if rec is None:
            continue
        store.add(row["ecosystem"], row["id"], rec)
        rel = f"{row['ecosystem']}/{row['id']}.json"
        pending_lines.append((row["modified"], row["ecosystem"], row["id"], rel))
        newest = max(newest, row["modified"])
        added += 1

    if pending_lines:
        outbox.mkdir(parents=True, exist_ok=True)
        with open(pending, "a", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            for line in pending_lines:
                writer.writerow(line)

    if newest:
        last_seen_path.write_text(newest, encoding="utf-8")
    return added


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def create_bundle(store_root: Path, outbox: Path, transport: Path) -> Path | None:
    """Collect pending records into a dated, self-contained transfer bundle.

    Copies each pending JSON file (preserving ``<ECOSYSTEM>/<ID>.json`` layout)
    plus a ``manifest.csv`` into ``transport/bundle_<stamp>/``, then moves the
    consumed ``pending.csv`` into ``outbox/archive`` for audit.
    """
    pending = outbox / "pending.csv"
    if not pending.exists():
        return None

    bundle_dir = transport / f"bundle_{_stamp()}"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    archive = outbox / "archive"
    archive.mkdir(parents=True, exist_ok=True)

    with open(pending, encoding="utf-8") as fh:
        rows = list(csv.reader(fh))

    with open(bundle_dir / "manifest.csv", "w", newline="", encoding="utf-8") as mf:
        writer = csv.writer(mf)
        writer.writerow(["modified", "ecosystem", "id", "relpath"])
        for row in rows:
            if len(row) < 4:
                continue
            writer.writerow(row)
            src = store_root / row[3]
            if src.exists():
                dst = bundle_dir / row[3]
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(src, dst)

    shutil.move(str(pending), str(archive / f"pending_{_stamp()}.csv"))
    return bundle_dir


def import_bundle(store: Any, bundle_dir: Path) -> int:
    """Load a transfer bundle's manifest + JSON files into the intranet store."""
    manifest = bundle_dir / "manifest.csv"
    if not manifest.exists():
        return 0
    added = 0
    with open(manifest, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            src = bundle_dir / row["relpath"]
            if not src.exists():
                continue
            rec = json.loads(src.read_text(encoding="utf-8"))
            store.add(row["ecosystem"], row["id"], rec)
            added += 1
    return added
