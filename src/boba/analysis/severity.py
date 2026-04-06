"""Severity assessment — CVSS 3.1 scoring and platform payout mapping."""

from __future__ import annotations

import math
from typing import Any

from boba.core.context import HuntContext
from boba.core.models import CVSSScore, Severity


# ═══════════════════ CVSS 3.1 Constants ═══════════════════
# From: https://www.first.org/cvss/v3.1/specification-document

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS roundup function: smallest number ≥ x with one decimal."""
    return math.ceil(x * 10) / 10


def calculate_cvss(
    attack_vector: str = "N",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "N",
    integrity: str = "N",
    availability: str = "N",
) -> CVSSScore:
    """Calculate CVSS 3.1 base score from metric values.

    Implements the CVSS 3.1 specification scoring formula exactly.
    """
    # Impact sub-score components
    isc_base = 1 - (1 - _CIA[confidentiality]) * (1 - _CIA[integrity]) * (1 - _CIA[availability])

    # Scope determines PR weights and impact formula
    if scope == "U":
        pr_weights = _PR_UNCHANGED
        impact = 6.42 * isc_base
    else:
        pr_weights = _PR_CHANGED
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base * 0.9731 - 0.02) ** 13

    # Exploitability sub-score
    exploitability = (
        8.22 * _AV[attack_vector] * _AC[attack_complexity]
        * pr_weights[privileges_required] * _UI[user_interaction]
    )

    # Base score
    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _roundup(min(impact + exploitability, 10))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10))

    vector = (
        f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}"
        f"/PR:{privileges_required}/UI:{user_interaction}"
        f"/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
    )

    return CVSSScore(
        score=score,
        vector=vector,
        severity=severity_from_score(score),
        attack_vector=attack_vector,
        attack_complexity=attack_complexity,
        privileges_required=privileges_required,
        user_interaction=user_interaction,
        scope=scope,
        confidentiality=confidentiality,
        integrity=integrity,
        availability=availability,
    )


def severity_from_score(score: float) -> Severity:
    """Map CVSS score to severity level per CVSS 3.1 spec."""
    if score == 0.0:
        return Severity.INFO
    if score <= 3.9:
        return Severity.LOW
    if score <= 6.9:
        return Severity.MEDIUM
    if score <= 8.9:
        return Severity.HIGH
    return Severity.CRITICAL


# ═══════════════════ Auto-scoring heuristics ═══════════════════

# Maps (finding_type, evidence_signals) → CVSS metric overrides
_AUTO_SCORE_RULES: dict[str, dict[str, str]] = {
    "idor": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "L", "user_interaction": "N",
        "scope": "U", "confidentiality": "H", "integrity": "L", "availability": "N",
    },
    "ssrf": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "C", "confidentiality": "H", "integrity": "N", "availability": "N",
    },
    "xss": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "R",
        "scope": "C", "confidentiality": "L", "integrity": "L", "availability": "N",
    },
    "sqli": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "H", "integrity": "H", "availability": "N",
    },
    "auth": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "H", "integrity": "H", "availability": "N",
    },
    "http": {  # Nuclei finding type — default to medium
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "L", "integrity": "N", "availability": "N",
    },
}


def auto_score_finding(finding: dict[str, Any]) -> CVSSScore:
    """Heuristic CVSS scoring based on finding type and evidence.

    Uses finding_type to select base metrics, then refines based on
    evidence signals (e.g., cloud metadata access upgrades SSRF severity).
    """
    ftype = finding.get("finding_type", "")
    metrics = dict(_AUTO_SCORE_RULES.get(ftype, {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "L", "integrity": "N", "availability": "N",
    }))

    # Evidence-based refinements
    evidence = finding.get("evidence")
    if isinstance(evidence, list):
        evidence_str = str(evidence).lower()

        if ftype == "idor":
            # Write IDOR is more severe than read
            if any(m in evidence_str for m in ["put", "post", "delete", "patch"]):
                metrics["integrity"] = "H"

        elif ftype == "ssrf":
            # Cloud metadata access → critical (credential theft + role escalation)
            if "cloud_metadata" in evidence_str or "169.254.169.254" in evidence_str:
                metrics["confidentiality"] = "H"
                metrics["integrity"] = "H"
            # OOB callback confirmed → higher confidence
            if "oob_callback" in evidence_str:
                metrics["confidentiality"] = "H"

        elif ftype == "xss":
            # Stored/DOM XSS: no user interaction needed (persisted payload)
            if "stored" in evidence_str or "dom_based" in evidence_str:
                metrics["user_interaction"] = "N"
            # Reflected XSS: UI:R is standard (user must click crafted link)

        elif ftype == "auth":
            # Admin access → availability impact too
            if "admin" in evidence_str or "privilege" in evidence_str:
                metrics["availability"] = "L"

    return calculate_cvss(**metrics)


# ═══════════════════ Platform payout mapping ═══════════════════

PAYOUT_TIERS: dict[str, dict[str, tuple[int, int]]] = {
    "hackerone": {
        "critical": (5_000, 50_000),
        "high": (2_500, 15_000),
        "medium": (750, 5_000),
        "low": (200, 1_500),
        "info": (0, 0),
    },
    "bugcrowd": {
        "critical": (5_500, 20_000),
        "high": (2_500, 7_500),
        "medium": (750, 1_500),
        "low": (250, 500),
        "info": (0, 0),
    },
}


def estimate_payout(
    severity: Severity, platform: str = "hackerone"
) -> tuple[int, int]:
    """Return (min, max) estimated payout for a severity level on a platform."""
    tiers = PAYOUT_TIERS.get(platform, PAYOUT_TIERS["hackerone"])
    return tiers.get(severity.value, (0, 0))


# ═══════════════════ Batch scoring ═══════════════════


def score_findings(
    context: HuntContext,
    hunt_id: str,
    finding_ids: list[int] | None = None,
    platform: str | None = None,
) -> list[dict[str, Any]]:
    """Score all (or specific) findings in a hunt.

    For each finding:
    1. Calculate CVSS via auto_score_finding()
    2. Attach payout estimate if platform specified
    3. Return scored finding dicts (does NOT mutate DB findings)
    """
    findings = context.get_findings(hunt_id)

    if finding_ids:
        id_set = set(finding_ids)
        findings = [f for f in findings if f["id"] in id_set]

    results = []
    for f in findings:
        cvss = auto_score_finding(f)
        scored = {
            "finding_id": f["id"],
            "title": f["title"],
            "finding_type": f["finding_type"],
            "original_severity": f["severity"],
            "cvss_score": cvss.score,
            "cvss_vector": cvss.vector,
            "cvss_severity": cvss.severity.value,
            "url": f.get("url"),
        }
        if platform:
            pmin, pmax = estimate_payout(cvss.severity, platform)
            scored["payout_min"] = pmin
            scored["payout_max"] = pmax
            scored["platform"] = platform

        results.append(scored)

    return results
