"""Filesystem-backed vulnerability store.

Mirrors the OSV.dev GCS layout exactly: ``<root>/<ECOSYSTEM>/<ID>.json``. This
keeps the data trivially copyable (rsync/scp) and makes the downloader map 1:1
onto the documented JSON + CSV sources. A SQL backend (SQL Server / Postgres)
can be dropped in later by implementing the same interface used by the matcher.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .matcher import index_keys_for_record


class JsonFileStore:
    """Loads and serves OSV records from a directory of JSON files."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._records: dict[str, dict[str, Any]] = {}
        self._index: dict[tuple[str, str], list[str]] = {}

    def load(self) -> None:
        """Load every ``*.json`` record under the root into memory."""
        self._records.clear()
        self._index.clear()
        if not self.root.exists():
            return
        for path in self.root.rglob("*.json"):
            try:
                rec = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            vuln_id = rec.get("id")
            if not vuln_id:
                continue
            self._records[vuln_id] = rec
            self._add_to_index(vuln_id, rec)

    def _add_to_index(self, vuln_id: str, rec: dict[str, Any]) -> None:
        for key in index_keys_for_record(rec):
            self._index.setdefault(key, [])
            if vuln_id not in self._index[key]:
                self._index[key].append(vuln_id)

    def get(self, vuln_id: str) -> dict[str, Any] | None:
        return self._records.get(vuln_id)

    def _remove_from_index(self, vuln_id: str) -> None:
        for key in list(self._index.keys()):
            entries = self._index[key]
            if vuln_id in entries:
                entries.remove(vuln_id)
                if not entries:
                    del self._index[key]

    def add(self, ecosystem: str, vuln_id: str, record: dict[str, Any]) -> None:
        """Insert/update a record in memory and persist it to disk."""
        self._remove_from_index(vuln_id)
        self._records[vuln_id] = record
        self._add_to_index(vuln_id, record)
        eco_dir = self.root / ecosystem
        eco_dir.mkdir(parents=True, exist_ok=True)
        (eco_dir / f"{vuln_id}.json").write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )

    def candidate_vulns(self, ecosystem: str, name: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for vuln_id in self._index.get((ecosystem.lower(), name), []):
            rec = self._records.get(vuln_id)
            if rec is not None:
                out.append(rec)
        return out

    def all_vulns(self) -> list[dict[str, Any]]:
        return list(self._records.values())
