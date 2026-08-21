"""OSV query matching engine.

Implements the OSV.dev query semantics against a local vulnerability store:

* A vulnerability matches a package query when one of its ``affected`` entries
  identifies the same package (by ``name``+``ecosystem`` OR by ``purl``).
* When a version is supplied, the version must fall inside an affected
  ``SEMVER``/``ECOSYSTEM`` range (or be listed in ``versions``). GIT ranges are
  ignored for version queries.
* When a commit is supplied, only GIT ranges are considered.
* When neither version nor commit is supplied, every vulnerability for the
  package is returned (this is what OSV.dev does for package-only queries).
* Withdrawn records are never returned.

This mirrors the public API closely enough to serve as an intranet mirror. The
one deliberate simplification vs. upstream OSV.dev is ecosystem-specific version
ordering: we use PEP 440 / semver via ``packaging`` with a numeric fallback,
rather than per-ecosystem comparators. For PyPI/npm/Go/Cargo this is faithful;
exotic ecosystems (Debian, Maven, etc.) may differ slightly.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

from packaging import version as pkg_version

PAGE_SIZE = 1000

# Map a purl ``type`` to the OSV ecosystem name used in the data dumps.
PURL_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "pypi": "PyPI",
    "pip": "PyPI",
    "npm": "npm",
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "golang": "Go",
    "go": "Go",
    "maven": "Maven",
    "gradle": "Maven",
    "gem": "RubyGems",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "packagist": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
    "hackage": "Haskell",
    "cocoapods": "SwiftURL",
    "generic": "",
    "oss-fuzz": "OSS-Fuzz",
    "bitnami": "Bitnami",
    "alpm": "Alpine",
    "apk": "Alpine",
    "deb": "Debian",
    "rpm": "Rocky Linux",
}


class VulnStore(Protocol):
    """Storage backend contract used by the matcher."""

    def candidate_vulns(self, ecosystem: str, name: str) -> list[dict[str, Any]]:
        """Return vulnerabilities whose ``affected`` list names this package."""
        ...

    def get(self, vuln_id: str) -> dict[str, Any] | None:
        """Return a single vulnerability record by id, or None."""
        ...

    def all_vulns(self) -> list[dict[str, Any]]:
        """Return every loaded vulnerability record."""
        ...


def normalize_ecosystem(ecosystem: str) -> str:
    """Lowercase + strip an ecosystem name for case-insensitive indexing."""
    return ecosystem.strip().lower()


def parse_purl(purl: str) -> tuple[str, str, str | None]:
    """Parse a purl into ``(ecosystem, name, version)``.

    The returned ecosystem is already mapped to the OSV ecosystem name.
    """
    if not purl.startswith("pkg:"):
        return "", "", None
    body = purl[4:].split("?", 1)[0]
    if "@" in body:
        path, version = body.rsplit("@", 1)
    else:
        path, version = body, None
    parts = [p for p in path.split("/") if p]
    if not parts:
        return "", "", version
    ptype = parts[0]
    name = parts[-1]
    ecosystem = PURL_TYPE_TO_ECOSYSTEM.get(ptype, ptype)
    return ecosystem, name, version


def index_keys_for_record(rec: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``(ecosystem_lower, name)`` keys an ``affected`` entry indexes under."""
    keys: list[tuple[str, str]] = []
    for affected in rec.get("affected", []):
        pkg = affected.get("package", {})
        eco = pkg.get("ecosystem")
        name = pkg.get("name")
        if eco and name:
            keys.append((normalize_ecosystem(eco), name))
        purl = pkg.get("purl")
        if purl:
            peco, pname, _ = parse_purl(purl)
            if peco and pname:
                keys.append((normalize_ecosystem(peco), pname))
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


class QueryError(ValueError):
    """Raised when a query is malformed (maps to HTTP 400)."""


def resolve_query(query: dict[str, Any]) -> dict[str, Any]:
    """Resolve a raw OSV query dict into ``ecosystem/name/version/commit``.

    Raises :class:`QueryError` for malformed requests (e.g. version supplied in
    both the top-level field and the purl).
    """
    package = query.get("package") or {}
    purl = package.get("purl")
    name = package.get("name")
    ecosystem = package.get("ecosystem")
    version = query.get("version")
    commit = query.get("commit")

    resolved_eco: str | None = None
    resolved_name: str | None = None
    purl_version: str | None = None

    if purl:
        peco, pname, purl_version = parse_purl(purl)
        resolved_eco = normalize_ecosystem(peco) if peco else None
        resolved_name = pname
        if purl_version and version:
            raise QueryError("version specified both in package.purl and top-level version")
    elif name and ecosystem:
        resolved_eco = normalize_ecosystem(ecosystem)
        resolved_name = name
    elif not commit:
        raise QueryError("package (name+ecosystem or purl) or commit is required")

    if not resolved_eco and not commit:
        raise QueryError("ecosystem is required when identifying a package by name")

    return {
        "ecosystem": resolved_eco,
        "name": resolved_name,
        "version": version or purl_version,
        "commit": commit,
    }


def _parse_version(v: str) -> pkg_version.Version:
    try:
        return pkg_version.parse(v)
    except pkg_version.InvalidVersion:
        parts = [p for p in re.split(r"[\.\D]+", v) if p]
        return pkg_version.parse(".".join(parts) if parts else "0")


def _ge(a: str, b: str) -> bool:
    return _parse_version(a) >= _parse_version(b)


def _lt(a: str, b: str) -> bool:
    return _parse_version(a) < _parse_version(b)


def _le(a: str, b: str) -> bool:
    return _parse_version(a) <= _parse_version(b)


def _matching_affected(rec: dict[str, Any], eco: str, name: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for affected in rec.get("affected", []):
        pkg = affected.get("package", {})
        a_eco = pkg.get("ecosystem")
        a_name = pkg.get("name")
        if a_eco and a_name and normalize_ecosystem(a_eco) == eco and a_name == name:
            out.append(affected)
            continue
        purl = pkg.get("purl")
        if purl:
            peco, pname, _ = parse_purl(purl)
            if peco and pname and normalize_ecosystem(peco) == eco and pname == name:
                out.append(affected)
    return out


def _version_in_range(version: str, rng: dict[str, Any]) -> bool:
    introduced: str | None = None
    for event in rng.get("events", []):
        if "introduced" in event:
            introduced = event["introduced"]
        if introduced is None:
            continue
        if "fixed" in event:
            if _ge(version, introduced) and _lt(version, event["fixed"]):
                return True
            introduced = None
        elif "last_affected" in event:
            if _ge(version, introduced) and _le(version, event["last_affected"]):
                return True
            introduced = None
        elif "limit" in event:
            if _ge(version, introduced) and _lt(version, event["limit"]):
                return True
            introduced = None
    if introduced is not None:
        return _ge(version, introduced)
    return False


def _affected_for_version(rec: dict[str, Any], eco: str, name: str, version: str) -> bool:
    for affected in _matching_affected(rec, eco, name):
        versions = affected.get("versions")
        if versions and version in versions:
            return True
        ranges = affected.get("ranges")
        if ranges:
            for rng in ranges:
                if rng.get("type") in ("SEMVER", "ECOSYSTEM") and _version_in_range(version, rng):
                    return True
            continue
        # No ranges and no versions list: all versions are affected.
        if not ranges and not versions:
            return True
    return False


def _affected_for_commit(rec: dict[str, Any], commit: str) -> bool:
    for affected in rec.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            introduced: str | None = None
            fixed: str | None = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            if introduced is None:
                continue
            if commit == introduced:
                return True
            if fixed is not None and commit == fixed:
                continue
            # Best-effort lexical ordering for GIT ranges (no graph available).
            if fixed is not None and introduced < commit < fixed:
                return True
    return False


def match_query(store: VulnStore, query: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the list of vulnerability records matching an OSV query dict."""
    resolved = resolve_query(query)
    eco = resolved["ecosystem"]
    name = resolved["name"]
    version = resolved["version"]
    commit = resolved["commit"]

    if commit and not eco:
        candidates = store.all_vulns()
    else:
        candidates = store.candidate_vulns(eco, name)

    results: list[dict[str, Any]] = []
    for rec in candidates:
        if rec.get("withdrawn"):
            continue
        if commit:
            if _affected_for_commit(rec, commit):
                results.append(rec)
        elif version:
            if _affected_for_version(rec, eco, name, version):
                results.append(rec)
        else:
            results.append(rec)
    return results
