"""Platform-specific report formatting — HackerOne, Bugcrowd, generic markdown."""

from __future__ import annotations

from boba.core.models import ReportDraft


def format_hackerone(report: ReportDraft) -> str:
    """Format report as HackerOne-compatible markdown.

    Structure follows HackerOne's recommended report format.
    """
    lines: list[str] = []

    # Title
    lines.append(f"## {report.title}")
    lines.append("")

    # Severity + CVSS
    lines.append(f"**Severity:** {report.severity.value.title()}")
    if report.cvss_vector:
        lines.append(f"**CVSS Score:** {report.cvss_score:.1f} ({report.cvss_vector})")
    lines.append("")

    # Summary
    lines.append("### Summary")
    lines.append("")
    lines.append(report.summary)
    lines.append("")

    # Steps to Reproduce
    lines.append("### Steps to Reproduce")
    lines.append("")
    for i, step in enumerate(report.steps, 1):
        lines.append(f"{i}. {step}")
    lines.append("")

    # Impact
    lines.append("### Impact")
    lines.append("")
    lines.append(report.impact)
    lines.append("")

    # Remediation
    if report.remediation:
        lines.append("### Remediation")
        lines.append("")
        lines.append(report.remediation)
        lines.append("")

    # Supporting Material
    if report.evidence_refs:
        lines.append("### Supporting Material/References")
        lines.append("")
        for ref in report.evidence_refs:
            lines.append(f"- {ref}")
        lines.append("")

    return "\n".join(lines)


def format_bugcrowd(report: ReportDraft) -> str:
    """Format report as Bugcrowd-compatible markdown.

    Includes VRT classification guidance.
    """
    lines: list[str] = []

    # Title
    lines.append(f"## {report.title}")
    lines.append("")

    # VRT Classification hint
    vrt = _severity_to_vrt(report.severity.value)
    lines.append(f"**VRT:** {vrt}")
    lines.append(f"**Severity:** {report.severity.value.title()}")
    if report.cvss_vector:
        lines.append(f"**CVSS:** {report.cvss_score:.1f}")
    lines.append("")

    # URL/Location
    if report.finding_id is not None or report.chain_id is not None:
        lines.append("### Location")
        lines.append("")
        # Steps will contain the URL info
        if report.steps:
            lines.append(report.steps[0])
        lines.append("")

    # Description
    lines.append("### Description")
    lines.append("")
    lines.append(report.summary)
    lines.append("")

    # Steps to Reproduce (skip first step if already shown as Location)
    lines.append("### Steps to Reproduce")
    lines.append("")
    has_location = report.steps and (report.finding_id is not None or report.chain_id is not None)
    start = 1 if has_location and len(report.steps) > 1 else 0
    for i, step in enumerate(report.steps[start:], start + 1):
        lines.append(f"{i}. {step}")
    lines.append("")

    # Impact
    lines.append("### Impact")
    lines.append("")
    lines.append(report.impact)
    lines.append("")

    # Severity Justification
    if report.cvss_vector:
        lines.append("### Severity Justification")
        lines.append("")
        lines.append(f"CVSS 3.1 Base Score: {report.cvss_score:.1f}")
        lines.append(f"Vector: {report.cvss_vector}")
        lines.append("")

    # Remediation
    if report.remediation:
        lines.append("### Remediation")
        lines.append("")
        lines.append(report.remediation)
        lines.append("")

    return "\n".join(lines)


def format_markdown(report: ReportDraft) -> str:
    """Format as generic markdown — suitable for self-hosted programs, email, or Jira."""
    lines: list[str] = []

    lines.append(f"# {report.title}")
    lines.append("")
    lines.append(
        f"**Severity:** {report.severity.value.title()} | **CVSS:** {report.cvss_score:.1f}"
    )
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(report.summary)
    lines.append("")

    lines.append("## Steps to Reproduce")
    lines.append("")
    for i, step in enumerate(report.steps, 1):
        lines.append(f"{i}. {step}")
    lines.append("")

    lines.append("## Impact")
    lines.append("")
    lines.append(report.impact)
    lines.append("")

    if report.remediation:
        lines.append("## Remediation")
        lines.append("")
        lines.append(report.remediation)
        lines.append("")

    if report.cvss_vector:
        lines.append("## CVSS Details")
        lines.append("")
        lines.append(f"- **Score:** {report.cvss_score:.1f}")
        lines.append(f"- **Vector:** {report.cvss_vector}")
        lines.append("")

    return "\n".join(lines)


def _severity_to_vrt(severity: str) -> str:
    """Map severity to approximate Bugcrowd VRT classification."""
    vrt_map = {
        "critical": "P1 — Critical",
        "high": "P2 — Severe",
        "medium": "P3 — Moderate",
        "low": "P4 — Low",
        "info": "P5 — Informational",
    }
    return vrt_map.get(severity, "Unclassified")
