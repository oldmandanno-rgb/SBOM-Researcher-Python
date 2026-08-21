"""FastAPI application exposing an OSV.dev-compatible API."""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .matcher import PAGE_SIZE, QueryError, match_query
from .models import BatchQuery, Query
from .store import JsonFileStore

DEFAULT_DATA_DIR = Path(os.environ.get("OSV_DATA_DIR", "./osv_data"))


def _encode_offset(offset: int) -> str:
    return base64.b64encode(str(offset).encode("utf-8")).decode("utf-8")


def _decode_offset(token: str) -> int:
    try:
        return int(base64.b64decode(token).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="invalid page_token")


def _paginate(vulns: list[dict[str, Any]], page_token: str | None) -> dict[str, Any]:
    offset = _decode_offset(page_token) if page_token else 0
    page = vulns[offset : offset + PAGE_SIZE]
    next_token = (
        _encode_offset(offset + PAGE_SIZE) if offset + PAGE_SIZE < len(vulns) else None
    )
    return {"vulns": page, "next_page_token": next_token}


def create_app(store: JsonFileStore | None = None) -> FastAPI:
    """Create the FastAPI app.

    If ``store`` is provided it is used directly (handy for tests); otherwise a
    :class:`JsonFileStore` is created from ``OSV_DATA_DIR`` and loaded.
    """
    app = FastAPI(title="OSV (local mirror)", version="1.0")

    if store is None:
        store = JsonFileStore(DEFAULT_DATA_DIR)
        store.load()
    app.state.store = store

    @app.post("/v1/query")
    def query(q: Query) -> dict[str, Any]:
        try:
            vulns = match_query(store, q.model_dump(exclude_none=True))
        except QueryError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return _paginate(vulns, q.page_token)

    @app.post("/v1/querybatch")
    def querybatch(bq: BatchQuery) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for q in bq.queries:
            try:
                vulns = match_query(store, q.model_dump(exclude_none=True))
            except QueryError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            page = _paginate(vulns, q.page_token)
            results.append(
                {
                    "vulns": [
                        {"id": v.get("id"), "modified": v.get("modified")} for v in page["vulns"]
                    ],
                    "next_page_token": page["next_page_token"],
                }
            )
        return {"results": results}

    @app.get("/v1/vulns/{vuln_id}")
    def get_vuln(vuln_id: str) -> Any:
        rec = store.get(vuln_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        return JSONResponse(content=rec)

    return app
