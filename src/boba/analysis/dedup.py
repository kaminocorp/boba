"""Finding deduplication — detect and group findings that share the same root cause."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from boba.core.context import HuntContext
from boba.core.models import DedupeGroup

logger = logging.getLogger(__name__)

# Confidence ranking for canonical selection (higher = preferred)

# Severity ranking for canonical selection (higher = preferred)
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Finding types that share the same vuln class for dedup purposes
_VULN_CLASS_ALIASES: dict[str, str] = {
    "http": "nuclei",  # Nuclei findings use finding_type="http"
}


def _normalize_vuln_class(finding_type: str) -> str:
    """Normalize finding type to a canonical vuln class for comparison."""
    return _VULN_CLASS_ALIASES.get(finding_type, finding_type)


def _extract_host(url: str | None) -> str:
    """Extract host from a URL, or return empty string."""
    if not url:
        return ""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _extract_path_stem(url: str | None) -> str:
    """Extract the path without the last segment (version-agnostic matching).

    /api/v1/users/123 → /api/v1/users
    /api/v2/users/456 → /api/v2/users
    """
    if not url:
        return ""
    try:
        path = urlparse(url).path.rstrip("/")
        parts = path.split("/")
        return "/".join(parts[:-1]) if len(parts) > 1 else path
    except Exception:
        return ""


def _select_canonical(findings: list[dict]) -> dict:
    """Select the best finding from a group to be the canonical representative.

    Priority: highest confidence → highest severity → most evidence → most recent.
    """
    def score(f: dict) -> tuple:
        conf = 3 if f.get("confirmed") else 1
        sev = _SEVERITY_RANK.get(f.get("severity", "info"), 0)
        evidence = f.get("evidence")
        ev_count = len(evidence) if isinstance(evidence, list) else 0
        return (conf, sev, ev_count, f.get("updated_at", ""))

    return max(findings, key=score)


def deduplicate_findings(
    context: HuntContext,
    hunt_id: str,
    dry_run: bool = False,
) -> list[DedupeGroup]:
    """Analyze all findings in a hunt and group duplicates.

    Dedup signals (in priority order):
    1. Exact URL + parameter match across different finding types
       (e.g., Nuclei finds SQLi on /search?q= AND test_sqli finds it)
    2. Same host + same parameter + same vuln class
       (e.g., /api/v1/users?id= and /api/v2/users?id= both have IDOR)

    For each group, selects a canonical finding (best confidence/severity/evidence).

    Returns groups. If not dry_run, also persists to dedup_groups table
    (clearing any previous groups first for idempotency).
    """
    findings = context.get_findings(hunt_id)
    if len(findings) < 2:
        return []

    # Build groups using a union-find approach keyed by dedup signals
    # Signal 1: exact (url, parameter, vuln_class)
    # Signal 2: (host, parameter, vuln_class) — broader match
    groups: dict[int, int] = {}  # finding_id → group_leader_id

    def find(fid: int) -> int:
        while groups.get(fid, fid) != fid:
            groups[fid] = groups.get(groups[fid], groups[fid])
            fid = groups[fid]
        return fid

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            groups[rb] = ra

    # Index findings by dedup keys
    by_url_param_exact: dict[tuple, list[int]] = {}
    by_url_param_typed: dict[tuple, list[int]] = {}
    by_host_param: dict[tuple, list[int]] = {}

    for f in findings:
        fid = f["id"]
        url = f.get("url") or ""
        param = f.get("parameter", "")
        ftype = _normalize_vuln_class(f.get("finding_type", ""))

        # Signal 1a: exact URL + param (cross-type — Nuclei + manual find same thing)
        if url:
            key1a = (url, param)
            by_url_param_exact.setdefault(key1a, []).append(fid)

        # Signal 1b: exact URL + param + vuln class
        if url and ftype:
            key1b = (url, param, ftype)
            by_url_param_typed.setdefault(key1b, []).append(fid)

        # Signal 2: host + param + vuln class (broader)
        host = _extract_host(url)
        if host and param and ftype:
            key2 = (host, param, ftype)
            by_host_param.setdefault(key2, []).append(fid)

    # Union findings that share a key
    for group_ids in by_url_param_exact.values():
        for i in range(1, len(group_ids)):
            union(group_ids[0], group_ids[i])

    for group_ids in by_url_param_typed.values():
        for i in range(1, len(group_ids)):
            union(group_ids[0], group_ids[i])

    for group_ids in by_host_param.values():
        for i in range(1, len(group_ids)):
            union(group_ids[0], group_ids[i])

    # Collect connected components
    components: dict[int, list[int]] = {}
    for f in findings:
        fid = f["id"]
        leader = find(fid)
        components.setdefault(leader, []).append(fid)

    # Build DedupeGroup for each component with >1 finding
    findings_by_id = {f["id"]: f for f in findings}
    result: list[DedupeGroup] = []

    for member_ids in components.values():
        if len(member_ids) < 2:
            continue

        member_findings = [findings_by_id[fid] for fid in member_ids]
        canonical = _select_canonical(member_findings)
        canonical_id = canonical["id"]

        # Build reason string
        urls = {f.get("url", "") for f in member_findings}
        types = {f.get("finding_type", "") for f in member_findings}
        if len(urls) == 1:
            reason = f"Same URL + parameter across finding types: {', '.join(sorted(types))}"
        else:
            host = _extract_host(canonical.get("url"))
            reason = f"Same host ({host}) + parameter + vuln class across endpoints"

        group = DedupeGroup(
            hunt_id=hunt_id,
            canonical_id=canonical_id,
            finding_ids=sorted(member_ids),
            reason=reason,
        )
        result.append(group)

    # Persist (idempotent: clear old groups first)
    if not dry_run and result:
        context.delete_dedup_groups(hunt_id)
        for g in result:
            g.id = context.insert_dedup_group(hunt_id, {
                "canonical_id": g.canonical_id,
                "finding_ids": g.finding_ids,
                "reason": g.reason,
            })

    return result


def check_duplicate(
    context: HuntContext,
    hunt_id: str,
    finding: dict,
) -> DedupeGroup | None:
    """Check if a single finding duplicates an existing one.

    Quick check without full re-analysis. Useful for inline duplicate
    detection during finding upsert.
    """
    url = finding.get("url") or ""
    param = finding.get("parameter", "")
    ftype = _normalize_vuln_class(finding.get("finding_type", ""))

    if not url or not ftype:
        return None

    all_findings = context.get_findings(hunt_id)
    host = _extract_host(url)

    for ef in all_findings:
        ef_url = ef.get("url") or ""
        ef_param = ef.get("parameter", "")
        ef_type = _normalize_vuln_class(ef.get("finding_type", ""))

        # Exact URL + parameter match (same or cross-type)
        if ef_url == url and ef_param == param:
            return DedupeGroup(
                canonical_id=ef["id"],
                finding_ids=[ef["id"]],
                reason=f"Exact URL + parameter match: {url}",
            )

        # Host + param match (same vuln class only)
        ef_host = _extract_host(ef_url)
        if ef_host == host and ef_param == param and param and ef_type == ftype:
            return DedupeGroup(
                canonical_id=ef["id"],
                finding_ids=[ef["id"]],
                reason=f"Same host ({host}) + parameter ({param})",
            )

    return None
