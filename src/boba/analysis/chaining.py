"""Vulnerability chaining — correlate findings into higher-severity attack chains."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

from boba.core.context import HuntContext
from boba.core.models import AttackChain, ChainStatus, Severity

logger = logging.getLogger(__name__)


# ═══════════════════ Chain Rules ═══════════════════


@dataclass
class ChainRule:
    """A known vulnerability chain pattern."""

    name: str
    description: str
    required_types: list[str]
    combined_severity: Severity
    impact: str
    same_host: bool = False
    min_findings: int = 0  # 0 = use len(required_types)
    evidence_keywords: list[str] = field(default_factory=list)


CHAIN_RULES: list[ChainRule] = [
    ChainRule(
        name="redirect_to_ssrf",
        description="Open redirect + SSRF → access internal network via trusted redirect",
        required_types=["redirect", "ssrf"],
        same_host=False,
        combined_severity=Severity.CRITICAL,
        impact="Attacker chains open redirect through SSRF to access internal services",
    ),
    ChainRule(
        name="xss_to_account_takeover",
        description="Stored XSS + CSRF bypass → account takeover",
        required_types=["xss", "csrf"],
        same_host=True,
        combined_severity=Severity.CRITICAL,
        impact="Stored XSS executes CSRF payload to change victim's email/password",
    ),
    ChainRule(
        name="idor_mass_exfil",
        description="IDOR with enumerable object IDs → mass data exfiltration",
        required_types=["idor"],
        min_findings=1,
        combined_severity=Severity.CRITICAL,
        impact="IDOR with predictable IDs allows enumeration of all user data",
        evidence_keywords=["enum", "sequential", "enumerated_id"],
    ),
    ChainRule(
        name="sqli_to_rce",
        description="SQL injection → potential RCE via stacked queries or file write",
        required_types=["sqli"],
        min_findings=1,
        combined_severity=Severity.CRITICAL,
        impact="SQL injection may allow OS command execution via stacked queries",
        evidence_keywords=["error_based", "time_based", "boolean_based"],
    ),
    ChainRule(
        name="auth_bypass_admin",
        description="Auth bypass + admin endpoint → full admin access",
        required_types=["auth"],
        min_findings=1,
        combined_severity=Severity.CRITICAL,
        impact="Authentication bypass grants access to admin functionality",
        evidence_keywords=["admin", "privilege", "no_auth_access"],
    ),
    ChainRule(
        name="ssrf_cloud_metadata",
        description="SSRF + cloud metadata access → credential theft",
        required_types=["ssrf"],
        min_findings=1,
        combined_severity=Severity.CRITICAL,
        impact="SSRF accesses cloud metadata service, leaking IAM credentials",
        evidence_keywords=["cloud_metadata", "169.254.169.254", "aws", "gcp"],
    ),
    ChainRule(
        name="xss_session_hijack",
        description="XSS + session cookie access → session hijacking",
        required_types=["xss"],
        min_findings=1,
        combined_severity=Severity.HIGH,
        impact="XSS can steal session cookies, enabling account takeover",
        evidence_keywords=["reflected", "dom_based", "stored", "cookie", "session"],
    ),
    ChainRule(
        name="idor_plus_sqli",
        description="IDOR + SQL injection → authenticated data exfiltration",
        required_types=["idor", "sqli"],
        same_host=True,
        combined_severity=Severity.CRITICAL,
        impact="IDOR provides valid object references for SQL injection data extraction",
    ),
]


def _extract_host(url: str | None) -> str:
    if not url:
        return ""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _evidence_contains(finding: dict, keywords: list[str]) -> bool:
    """Check if finding evidence contains any of the given keywords."""
    evidence = finding.get("evidence")
    if not isinstance(evidence, list):
        return False
    evidence_str = str(evidence).lower()
    return any(kw.lower() in evidence_str for kw in keywords)


def _get_non_duplicate_findings(context: HuntContext, hunt_id: str) -> list[dict]:
    """Get findings excluding non-canonical dedup group members."""
    findings = context.get_findings(hunt_id)
    dedup_groups = context.get_dedup_groups(hunt_id)

    # Build set of non-canonical finding IDs
    non_canonical: set[int] = set()
    for group in dedup_groups:
        canonical_id = group["canonical_id"]
        for fid in group["finding_ids"]:
            if fid != canonical_id:
                non_canonical.add(fid)

    return [f for f in findings if f["id"] not in non_canonical]


# ═══════════════════ Chain Detection ═══════════════════


def detect_chains(
    context: HuntContext,
    hunt_id: str,
) -> list[AttackChain]:
    """Analyze all non-duplicate findings and detect applicable chains.

    Checks each ChainRule against the finding set. Persists detected chains
    (idempotent: clears previous chains first).
    """
    findings = _get_non_duplicate_findings(context, hunt_id)
    if not findings:
        return []

    # Index by type and host
    by_type: dict[str, list[dict]] = {}
    by_host_type: dict[tuple[str, str], list[dict]] = {}

    for f in findings:
        ftype = f.get("finding_type", "")
        by_type.setdefault(ftype, []).append(f)
        host = _extract_host(f.get("url"))
        if host:
            by_host_type.setdefault((host, ftype), []).append(f)

    chains: list[AttackChain] = []

    for rule in CHAIN_RULES:
        matched = _match_rule(rule, findings, by_type, by_host_type)
        if matched:
            chains.append(matched)

    # Persist (idempotent: always clear previous chains, then insert new ones)
    context.delete_chains(hunt_id)
    if chains:
        for chain in chains:
            chain.id = context.upsert_chain(hunt_id, {
                "title": chain.title,
                "description": chain.description,
                "severity": chain.severity.value,
                "confidence": chain.confidence.value,
                "cvss_score": chain.cvss_score,
                "cvss_vector": chain.cvss_vector,
                "finding_ids": chain.finding_ids,
                "chain_order": chain.chain_order,
                "impact": chain.impact,
                "prerequisites": chain.prerequisites,
                "tags": chain.tags,
            })

    return chains


def _match_rule(
    rule: ChainRule,
    findings: list[dict],
    by_type: dict[str, list[dict]],
    by_host_type: dict[tuple[str, str], list[dict]],
) -> AttackChain | None:
    """Try to match a single chain rule against the finding set."""
    required = rule.required_types
    min_count = rule.min_findings or len(required)

    if len(required) == 1:
        # Single-type rule with evidence requirements
        ftype = required[0]
        candidates = by_type.get(ftype, [])
        if not candidates:
            return None

        # Filter by evidence keywords if specified
        if rule.evidence_keywords:
            matching = [f for f in candidates if _evidence_contains(f, rule.evidence_keywords)]
            if not matching:
                return None
            candidates = matching

        if len(candidates) < min_count:
            return None

        finding_ids = [f["id"] for f in candidates]
        return _build_chain(rule, candidates, finding_ids)

    # Multi-type rule: need at least one finding per required type
    type_matches: dict[str, list[dict]] = {}
    for rtype in required:
        if rule.same_host:
            # Need all types present on the same host
            pass  # handled below
        else:
            matches = by_type.get(rtype, [])
            if not matches:
                return None
            type_matches[rtype] = matches

    if rule.same_host:
        # Find hosts that have all required types
        hosts_with_types: dict[str, dict[str, list[dict]]] = {}
        for rtype in required:
            for f in by_type.get(rtype, []):
                host = _extract_host(f.get("url"))
                if host:
                    hosts_with_types.setdefault(host, {}).setdefault(rtype, []).append(f)

        for host, type_map in hosts_with_types.items():
            if all(rtype in type_map for rtype in required):
                all_findings = []
                for rtype in required:
                    all_findings.extend(type_map[rtype])
                finding_ids = [f["id"] for f in all_findings]
                return _build_chain(rule, all_findings, finding_ids)
        return None

    # Cross-host: just need one of each type
    all_findings = []
    for rtype in required:
        all_findings.append(type_matches[rtype][0])
    finding_ids = [f["id"] for f in all_findings]
    return _build_chain(rule, all_findings, finding_ids)


def _build_chain(
    rule: ChainRule,
    findings: list[dict],
    finding_ids: list[int],
) -> AttackChain:
    """Construct an AttackChain from a matched rule and its findings."""
    # Score the chain — use the rule's combined severity to determine CVSS
    cvss = _chain_cvss(rule.combined_severity)

    # Order findings by attack sequence (matching required_types order)
    type_order = {t: i for i, t in enumerate(rule.required_types)}
    fid_to_type = {f["id"]: f.get("finding_type", "") for f in findings}
    ordered = sorted(
        finding_ids,
        key=lambda fid: type_order.get(fid_to_type.get(fid, ""), 999),
    )

    return AttackChain(
        hunt_id="",  # set by caller
        title=rule.description,
        description=f"Chain: {rule.name}",
        severity=rule.combined_severity,
        confidence=ChainStatus.HYPOTHETICAL,
        cvss_score=cvss.score,
        cvss_vector=cvss.vector,
        finding_ids=sorted(finding_ids),
        chain_order=ordered,
        impact=rule.impact,
        tags=[rule.name],
    )


def _chain_cvss(severity: Severity):
    """Generate a representative CVSS score for a chain severity."""
    from boba.analysis.severity import calculate_cvss

    if severity == Severity.CRITICAL:
        return calculate_cvss(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="C", confidentiality="H", integrity="H", availability="N",
        )
    if severity == Severity.HIGH:
        return calculate_cvss(
            attack_vector="N", attack_complexity="L",
            privileges_required="L", user_interaction="N",
            scope="U", confidentiality="H", integrity="H", availability="N",
        )
    return calculate_cvss(
        attack_vector="N", attack_complexity="L",
        privileges_required="L", user_interaction="N",
        scope="U", confidentiality="L", integrity="L", availability="N",
    )


# ═══════════════════ Targeted Suggestion ═══════════════════


def suggest_chains(
    context: HuntContext,
    hunt_id: str,
    finding_ids: list[int],
) -> list[AttackChain]:
    """Given specific findings, suggest possible chains.

    Unlike detect_chains (which scans all findings), this is targeted.
    Does NOT persist results.
    """
    findings = context.get_findings(hunt_id)
    target_findings = [f for f in findings if f["id"] in set(finding_ids)]

    if not target_findings:
        return []

    by_type: dict[str, list[dict]] = {}
    by_host_type: dict[tuple[str, str], list[dict]] = {}
    for f in findings:
        ftype = f.get("finding_type", "")
        by_type.setdefault(ftype, []).append(f)
        host = _extract_host(f.get("url"))
        if host:
            by_host_type.setdefault((host, ftype), []).append(f)

    chains: list[AttackChain] = []
    target_types = {f.get("finding_type", "") for f in target_findings}

    for rule in CHAIN_RULES:
        # Only suggest rules relevant to the target findings
        if not any(rt in target_types for rt in rule.required_types):
            continue
        matched = _match_rule(rule, findings, by_type, by_host_type)
        if matched:
            # Only include if at least one target finding is in the chain
            if any(fid in set(finding_ids) for fid in matched.finding_ids):
                chains.append(matched)

    return chains


# ═══════════════════ Validation ═══════════════════


def validate_chain(
    context: HuntContext,
    hunt_id: str,
    chain_id: int,
) -> AttackChain | None:
    """Mark a chain as validated after confirmation.

    Updates confidence from HYPOTHETICAL to VALIDATED.
    Returns the updated chain, or None if not found.
    """
    chain = context.get_chain(chain_id)
    if not chain:
        return None

    context.update_chain_confidence(chain_id, ChainStatus.VALIDATED.value)

    chain["confidence"] = ChainStatus.VALIDATED.value
    return AttackChain(
        id=chain["id"],
        hunt_id=chain["hunt_id"],
        title=chain["title"],
        description=chain.get("description", ""),
        severity=Severity(chain.get("severity", "info")),
        confidence=ChainStatus.VALIDATED,
        cvss_score=chain.get("cvss_score", 0.0),
        cvss_vector=chain.get("cvss_vector", ""),
        finding_ids=chain.get("finding_ids", []),
        chain_order=chain.get("chain_order", []),
        impact=chain.get("impact", ""),
        prerequisites=chain.get("prerequisites", []),
        tags=chain.get("tags", []),
    )
