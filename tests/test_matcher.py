"""Tests for the OSV query matching engine (osv_service.matcher)."""

from __future__ import annotations

import pytest

from osv_service.matcher import (
    PURL_TYPE_TO_ECOSYSTEM,
    QueryError,
    _affected_for_commit,
    _affected_for_version,
    _ge,
    _le,
    _lt,
    _matching_affected,
    _parse_version,
    _version_in_range,
    index_keys_for_record,
    match_query,
    normalize_ecosystem,
    parse_purl,
    resolve_query,
)


class FakeStore:
    """Minimal in-memory VulnStore used to drive match_query."""

    def __init__(self, records: list[dict]) -> None:
        self._records = records

    def candidate_vulns(self, ecosystem: str, name: str) -> list[dict]:
        eco = ecosystem.lower()
        out: list[dict] = []
        for rec in self._records:
            for aff in rec.get("affected", []):
                pkg = aff.get("package", {})
                if (
                    pkg.get("ecosystem", "").lower() == eco
                    and pkg.get("name") == name
                ):
                    out.append(rec)
                    break
        return out

    def get(self, vuln_id: str) -> dict | None:
        return next((r for r in self._records if r.get("id") == vuln_id), None)

    def all_vulns(self) -> list[dict]:
        return list(self._records)


# --- normalize_ecosystem -----------------------------------------------------


def test_normalize_ecosystem_strips_and_lowercases() -> None:
    assert normalize_ecosystem(" PyPI ") == "pypi"
    assert normalize_ecosystem("Crates.Io") == "crates.io"


# --- parse_purl --------------------------------------------------------------


def test_parse_purl_basic() -> None:
    assert parse_purl("pkg:pypi/django@4.2") == ("PyPI", "django", "4.2")


def test_parse_purl_no_version() -> None:
    assert parse_purl("pkg:npm/left-pad") == ("npm", "left-pad", None)


def test_parse_purl_nested_path() -> None:
    # Last path segment is the package name; purl type maps to ecosystem.
    assert parse_purl("pkg:golang/github.com/foo/bar@1.0") == ("Go", "bar", "1.0")


def test_parse_purl_strips_query() -> None:
    assert parse_purl("pkg:pypi/foo@1.0?foo=bar") == ("PyPI", "foo", "1.0")


def test_parse_purl_non_purl() -> None:
    assert parse_purl("not-a-purl") == ("", "", None)


# --- PURL_TYPE_TO_ECOSYSTEM --------------------------------------------------


def test_purl_type_mapping_subset() -> None:
    assert PURL_TYPE_TO_ECOSYSTEM["pip"] == "PyPI"
    assert PURL_TYPE_TO_ECOSYSTEM["golang"] == "Go"
    assert PURL_TYPE_TO_ECOSYSTEM["cargo"] == "crates.io"
    assert PURL_TYPE_TO_ECOSYSTEM["maven"] == "Maven"
    assert PURL_TYPE_TO_ECOSYSTEM["gem"] == "RubyGems"
    assert PURL_TYPE_TO_ECOSYSTEM["generic"] == ""


def test_purl_type_unknown_maps_to_self() -> None:
    assert parse_purl("pkg:mystery/foo@1.0") == ("mystery", "foo", "1.0")


# --- index_keys_for_record ---------------------------------------------------


def test_index_keys_package_only() -> None:
    rec = {"affected": [{"package": {"name": "foo", "ecosystem": "PyPI"}}]}
    assert index_keys_for_record(rec) == [("pypi", "foo")]


def test_index_keys_purl() -> None:
    rec = {"affected": [{"package": {"purl": "pkg:pypi/foo@1.0"}}]}
    assert index_keys_for_record(rec) == [("pypi", "foo")]


def test_index_keys_dedupes() -> None:
    rec = {
        "affected": [
            {"package": {"name": "foo", "ecosystem": "PyPI"}},
            {"package": {"purl": "pkg:pypi/foo@1.0"}},
        ]
    }
    assert index_keys_for_record(rec) == [("pypi", "foo")]


def test_index_keys_empty() -> None:
    assert index_keys_for_record({}) == []


# --- resolve_query -----------------------------------------------------------


def test_resolve_query_name_ecosystem() -> None:
    q = resolve_query({"package": {"name": "foo", "ecosystem": "PyPI"}})
    assert q == {"ecosystem": "pypi", "name": "foo", "version": None, "commit": None}


def test_resolve_query_name_ecosystem_with_version() -> None:
    q = resolve_query({"package": {"name": "foo", "ecosystem": "PyPI"}, "version": "1.0"})
    assert q["version"] == "1.0"


def test_resolve_query_purl() -> None:
    q = resolve_query({"package": {"purl": "pkg:pypi/foo@1.0"}})
    assert q["ecosystem"] == "pypi"
    assert q["name"] == "foo"
    assert q["version"] == "1.0"


def test_resolve_query_version_in_both_raises() -> None:
    with pytest.raises(QueryError):
        resolve_query({"package": {"purl": "pkg:pypi/foo@1.0"}, "version": "2.0"})


def test_resolve_query_commit_only() -> None:
    q = resolve_query({"commit": "abc123"})
    assert q["commit"] == "abc123"
    assert q["ecosystem"] is None
    assert q["name"] is None


def test_resolve_query_name_without_ecosystem_raises() -> None:
    with pytest.raises(QueryError):
        resolve_query({"package": {"name": "foo"}})


def test_resolve_query_empty_raises() -> None:
    with pytest.raises(QueryError):
        resolve_query({})


# --- version parsing / comparison helpers ------------------------------------


def test_version_comparisons() -> None:
    assert _ge("1.2.3", "1.2.0")
    assert _lt("1.2.0", "1.2.3")
    assert _le("1.2.3", "1.2.3")
    assert not _ge("1.0.0", "2.0.0")


def test_parse_version_invalid_falls_back_to_numeric() -> None:
    # Non-numeric junk collapses to "0"; leading 'v' is stripped.
    assert _parse_version("v1.2.3") == _parse_version("1.2.3")
    assert _parse_version("abc") == _parse_version("0")


# --- _version_in_range -------------------------------------------------------


def test_version_in_range_open_introduced() -> None:
    rng = {"events": [{"introduced": "1.0.0"}]}
    assert _version_in_range("2.0.0", rng)
    assert not _version_in_range("0.5.0", rng)


def test_version_in_range_fixed() -> None:
    rng = {"events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}
    assert _version_in_range("1.5.0", rng)
    assert not _version_in_range("2.0.0", rng)
    assert not _version_in_range("0.9.0", rng)


def test_version_in_range_last_affected() -> None:
    rng = {"events": [{"introduced": "1.0.0"}, {"last_affected": "2.0.0"}]}
    assert _version_in_range("2.0.0", rng)
    assert not _version_in_range("2.1.0", rng)


def test_version_in_range_limit() -> None:
    rng = {"events": [{"introduced": "1.0.0"}, {"limit": "2.0.0"}]}
    assert _version_in_range("1.9.0", rng)
    assert not _version_in_range("2.0.0", rng)


# --- _matching_affected ------------------------------------------------------


def test_matching_affected_by_package() -> None:
    rec = {"affected": [{"package": {"name": "foo", "ecosystem": "PyPI"}}]}
    assert _matching_affected(rec, "pypi", "foo")


def test_matching_affected_by_purl() -> None:
    rec = {"affected": [{"package": {"purl": "pkg:pypi/foo@1.0"}}]}
    assert _matching_affected(rec, "pypi", "foo")


def test_matching_affected_no_match() -> None:
    rec = {"affected": [{"package": {"name": "bar", "ecosystem": "PyPI"}}]}
    assert not _matching_affected(rec, "pypi", "foo")


# --- _affected_for_version ---------------------------------------------------


def test_affected_for_version_versions_list() -> None:
    affected = {"package": {"name": "foo", "ecosystem": "PyPI"}, "versions": ["1.0", "1.1"]}
    assert _affected_for_version({"affected": [affected]}, "pypi", "foo", "1.0")
    assert not _affected_for_version({"affected": [affected]}, "pypi", "foo", "2.0")


def test_affected_for_version_semver_range() -> None:
    affected = {
        "package": {"name": "foo", "ecosystem": "PyPI"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
    }
    assert _affected_for_version({"affected": [affected]}, "pypi", "foo", "1.5.0")
    assert not _affected_for_version({"affected": [affected]}, "pypi", "foo", "2.5.0")


def test_affected_for_version_git_only_does_not_match() -> None:
    # A GIT-only range must be ignored for version queries.
    affected = {
        "package": {"name": "foo", "ecosystem": "PyPI"},
        "ranges": [{"type": "GIT", "events": [{"introduced": "a"}, {"fixed": "b"}]}],
    }
    assert not _affected_for_version({"affected": [affected]}, "pypi", "foo", "1.0.0")


def test_affected_for_version_no_ranges_no_versions() -> None:
    # No version constraints means every version is affected.
    affected = {"package": {"name": "foo", "ecosystem": "PyPI"}}
    assert _affected_for_version({"affected": [affected]}, "pypi", "foo", "9.9.9")


# --- _affected_for_commit ----------------------------------------------------


def test_affected_for_commit_between() -> None:
    rng = {"type": "GIT", "events": [{"introduced": "aaa"}, {"fixed": "zzz"}]}
    affected = {"package": {"name": "foo"}, "ranges": [rng]}
    assert _affected_for_commit({"affected": [affected]}, "mmm")


def test_affected_for_commit_at_introduced() -> None:
    rng = {"type": "GIT", "events": [{"introduced": "aaa"}, {"fixed": "zzz"}]}
    affected = {"package": {"name": "foo"}, "ranges": [rng]}
    assert _affected_for_commit({"affected": [affected]}, "aaa")


def test_affected_for_commit_at_fixed_is_excluded() -> None:
    rng = {"type": "GIT", "events": [{"introduced": "aaa"}, {"fixed": "zzz"}]}
    affected = {"package": {"name": "foo"}, "ranges": [rng]}
    assert not _affected_for_commit({"affected": [affected]}, "zzz")


def test_affected_for_commit_open_range_no_match() -> None:
    rng = {"type": "GIT", "events": [{"introduced": "aaa"}]}
    affected = {"package": {"name": "foo"}, "ranges": [rng]}
    assert not _affected_for_commit({"affected": [affected]}, "bbb")


def test_affected_for_commit_non_git_ignored() -> None:
    rng = {"type": "SEMVER", "events": [{"introduced": "1.0.0"}]}
    affected = {"package": {"name": "foo"}, "ranges": [rng]}
    assert not _affected_for_commit({"affected": [affected]}, "1.0.0")


# --- match_query -------------------------------------------------------------


def test_match_query_package_only_excludes_withdrawn() -> None:
    records = [
        {"id": "V1", "affected": [{"package": {"name": "foo", "ecosystem": "PyPI"}}]},
        {
            "id": "V2",
            "withdrawn": "2024-01-01T00:00:00Z",
            "affected": [{"package": {"name": "foo", "ecosystem": "PyPI"}}],
        },
    ]
    store = FakeStore(records)
    result = match_query(store, {"package": {"name": "foo", "ecosystem": "PyPI"}})
    assert [r["id"] for r in result] == ["V1"]


def test_match_query_version_filters() -> None:
    records = [
        {
            "id": "V1",
            "affected": [
                {
                    "package": {"name": "foo", "ecosystem": "PyPI"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
                }
            ],
        },
        # Different package: never a candidate for foo.
        {"id": "V2", "affected": [{"package": {"name": "other", "ecosystem": "PyPI"}}]},
    ]
    store = FakeStore(records)
    hit = match_query(store, {"package": {"name": "foo", "ecosystem": "PyPI"}, "version": "1.5.0"})
    assert [r["id"] for r in hit] == ["V1"]
    miss = match_query(store, {"package": {"name": "foo", "ecosystem": "PyPI"}, "version": "3.0.0"})
    assert miss == []


def test_match_query_commit_path() -> None:
    records = [
        {
            "id": "V1",
            "affected": [
                {"package": {"name": "foo"}, "ranges": [{"type": "GIT", "events": [{"introduced": "aaa"}, {"fixed": "zzz"}]}]}
            ],
        },
        {"id": "V2", "affected": [{"package": {"name": "foo"}}]},
    ]
    store = FakeStore(records)
    hit = match_query(store, {"commit": "mmm"})
    assert [r["id"] for r in hit] == ["V1"]


def test_match_query_only_matching_package_returned() -> None:
    records = [
        {"id": "V1", "affected": [{"package": {"name": "foo", "ecosystem": "PyPI"}}]},
        {"id": "V2", "affected": [{"package": {"name": "other", "ecosystem": "PyPI"}}]},
    ]
    store = FakeStore(records)
    result = match_query(store, {"package": {"name": "foo", "ecosystem": "PyPI"}})
    assert [r["id"] for r in result] == ["V1"]
