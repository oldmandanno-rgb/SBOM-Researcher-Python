"""Pydantic request/response models mirroring osv_service_v1.swagger.json."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class Package(BaseModel):
    name: str | None = None
    ecosystem: str | None = None
    purl: str | None = None


class Query(BaseModel):
    commit: str | None = None
    version: str | None = None
    package: Package | None = None
    page_token: str | None = None


class BatchQuery(BaseModel):
    queries: list[Query] = []


class OSVVulnerability(BaseModel):
    """Loose model that preserves every field of an OSV record."""

    model_config = ConfigDict(extra="allow")
    id: str | None = None


class VulnerabilityList(BaseModel):
    vulns: list[dict[str, Any]] = []
    next_page_token: str | None = None


class BatchVulnerabilityList(BaseModel):
    results: list[VulnerabilityList] = []
