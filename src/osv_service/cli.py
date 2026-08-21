"""Command line interface for the local OSV.dev mirror.

Two deployment modes:

* **DMZ copy** (talks to GCS): ``download`` (optionally ``--loop``) syncs new
  records, then ``bundle`` packages them for manual transfer.
* **Intranet copy** (never touches GCS): set ``OSV_SYNC_ENABLED=0``, then
  ``import-bundle`` to ingest a bundle and ``serve`` to answer queries.

DNS on the intranet points ``api.osv.dev`` at the intranet copy, so existing
tools (SBOM-Researcher included) need no configuration changes.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import click
import httpx

from .app import DEFAULT_DATA_DIR, create_app
from .downloader import create_bundle, import_bundle, sync_once
from .store import JsonFileStore


def _sync_enabled() -> bool:
    return os.environ.get("OSV_SYNC_ENABLED", "1") != "0"


@click.group()
def main() -> None:
    """Local OSV.dev mirror service."""


@main.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8000, type=int, show_default=True)
@click.option("--data-dir", default=str(DEFAULT_DATA_DIR), show_default=True)
def serve(host: str, port: int, data_dir: str) -> None:
    """Serve the OSV-compatible API from a local store."""
    store = JsonFileStore(Path(data_dir))
    store.load()
    app = create_app(store)
    import uvicorn

    uvicorn.run(app, host=host, port=port)


@main.command()
@click.option("--data-dir", default=str(DEFAULT_DATA_DIR), show_default=True)
@click.option("--outbox", default="./osv_outbox", show_default=True)
@click.option("--ecosystem", default=None, help="Limit sync to one ecosystem.")
@click.option("--loop", is_flag=True, help="Repeat sync on an interval.")
@click.option(
    "--interval",
    default=86400,
    type=int,
    show_default=True,
    help="Seconds between sync passes (default 86400 = 1 day).",
)
def download(
    data_dir: str, outbox: str, ecosystem: str | None, loop: bool, interval: int
) -> None:
    """Sync new/updated records from GCS (DMZ copy only)."""
    if not _sync_enabled():
        click.echo("Sync disabled (OSV_SYNC_ENABLED=0). This is the intranet copy.")
        return
    store = JsonFileStore(Path(data_dir))
    store.load()
    outbox_path = Path(outbox)
    last_seen = outbox_path / "last_seen.txt"
    with httpx.Client(timeout=60.0) as client:
        while True:
            added = sync_once(store, outbox_path, last_seen, client, ecosystem)
            click.echo(f"Synced {added} new record(s).")
            if not loop:
                break
            time.sleep(interval)


@main.command()
@click.option("--data-dir", default=str(DEFAULT_DATA_DIR), show_default=True)
@click.option("--outbox", default="./osv_outbox", show_default=True)
@click.option("--transport", default="./osv_transport", show_default=True)
def bundle(data_dir: str, outbox: str, transport: str) -> None:
    """Package pending records into a dated bundle for DMZ transfer."""
    store = JsonFileStore(Path(data_dir))
    store.load()
    result = create_bundle(Path(data_dir), Path(outbox), Path(transport))
    if result is None:
        click.echo("Nothing pending to bundle.")
    else:
        click.echo(f"Bundle created: {result}")


@main.command(name="import-bundle")
@click.option("--data-dir", default=str(DEFAULT_DATA_DIR), show_default=True)
@click.option("--path", required=True, help="Path to a bundle_<stamp> directory.")
def import_bundle_cmd(data_dir: str, path: str) -> None:
    """Ingest a transfer bundle into the intranet store."""
    store = JsonFileStore(Path(data_dir))
    store.load()
    added = import_bundle(store, Path(path))
    click.echo(f"Imported {added} record(s).")


if __name__ == "__main__":
    main()
