"""Coverage tracking — what's been tested and what hasn't."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from boba.core.context import HuntContext
from boba.core.models import CoverageSummary


# Default vulnerability test types that coverage gap analysis checks against
DEFAULT_TEST_TYPES = ["idor", "ssrf", "xss", "sqli", "auth"]


def get_coverage_summary(
    context: HuntContext,
    hunt_id: str,
    host: str | None = None,
    test_types: list[str] | None = None,
) -> CoverageSummary:
    """Aggregate coverage stats: total endpoints, tested, untested, per-test-type breakdown.

    Endpoints are discovered from urls + directories tables.
    Coverage is checked against the coverage table.
    """
    types = test_types or DEFAULT_TEST_TYPES

    # Count unique endpoint URLs from urls + directories
    all_endpoints = _get_known_endpoints(context, hunt_id, host)
    total = len(all_endpoints)

    # Get coverage records
    coverage_records = context.get_coverage(hunt_id, host=host)

    # Tested = endpoints that have at least one coverage row
    tested_urls = {r["url"] for r in coverage_records}
    tested = len(all_endpoints & tested_urls)

    # Per-test-type counts
    type_counts: dict[str, int] = {}
    for r in coverage_records:
        tt = r["test_type"]
        type_counts[tt] = type_counts.get(tt, 0) + 1

    # Gaps = untested (url, test_type) pairs
    gaps = context.get_untested_endpoints(hunt_id, test_types=types)

    return CoverageSummary(
        total_endpoints=total,
        tested_endpoints=tested,
        untested_endpoints=total - tested,
        coverage_by_test_type=type_counts,
        gaps=gaps,
    )


def get_coverage_gaps(
    context: HuntContext,
    hunt_id: str,
    test_types: list[str] | None = None,
    host: str | None = None,
) -> list[dict[str, Any]]:
    """Return untested (url, method, test_type) combinations.

    If host is provided, only return gaps for endpoints on that host.
    """
    types = test_types or DEFAULT_TEST_TYPES
    gaps = context.get_untested_endpoints(hunt_id, test_types=types)

    if host:
        gaps = [g for g in gaps if urlparse(g.get("url", "")).hostname == host]

    return gaps


def _get_known_endpoints(
    context: HuntContext, hunt_id: str, host: str | None = None
) -> set[str]:
    """Collect unique endpoint URLs from urls + directories tables."""
    urls = context.get_urls(hunt_id, host=host)
    directories = context.get_directories(hunt_id)

    endpoint_set: set[str] = set()
    for u in urls:
        endpoint_set.add(u["url"])
    for d in directories:
        endpoint_set.add(d["url"])

    if host and directories:
        endpoint_set = {ep for ep in endpoint_set if urlparse(ep).hostname == host}

    return endpoint_set
