"""Report drafting — generate structured reports from findings and chains."""

from __future__ import annotations

from boba.analysis.severity import auto_score_finding
from boba.core.context import HuntContext
from boba.core.models import ReportDraft, ReportStatus, Severity


# Vuln-type-specific remediation suggestions
_REMEDIATION: dict[str, str] = {
    "idor": "Implement server-side authorization checks on every resource access. "
    "Verify the requesting user owns or has permission to access the resource.",
    "ssrf": "Validate and whitelist allowed URLs server-side. Block requests to internal "
    "IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). Use an allowlist, not a denylist.",
    "xss": "Encode all user-controlled output contextually (HTML entity, JS string, URL, CSS). "
    "Implement a strict Content-Security-Policy header.",
    "sqli": "Use parameterized queries (prepared statements) for all database access. "
    "Never concatenate user input into SQL strings.",
    "auth": "Enforce authentication on all protected endpoints. Validate JWT signatures "
    "server-side with a strong algorithm (RS256). Implement role-based access control.",
}


def draft_finding_report(
    context: HuntContext,
    hunt_id: str,
    finding_id: int,
) -> ReportDraft:
    """Generate a structured report for a single finding.

    Pulls from finding record, HTTP history, and CVSS scoring.
    Persists the draft to the reports table.
    """
    finding = context.get_finding_by_id(finding_id)
    if not finding:
        raise ValueError(f"Finding {finding_id} not found")

    ftype = finding.get("finding_type", "unknown")
    url = finding.get("url", "")
    param = finding.get("parameter", "")

    # CVSS scoring
    cvss = auto_score_finding(finding)

    # Title: [Component] [Vuln Type] leads to [Impact]
    component = _extract_component(url)
    title = _build_title(ftype, component, param)

    # Summary
    summary = _build_summary(finding, ftype, url, param)

    # Steps to reproduce from evidence + HTTP history
    steps = _build_steps(context, finding)

    # Impact statement
    impact = _build_impact(finding, ftype)

    # Remediation
    remediation = _REMEDIATION.get(ftype, "Review and fix the identified vulnerability.")

    # Collect request IDs
    request_ids = finding.get("request_ids", [])
    if not isinstance(request_ids, list):
        request_ids = []

    # Build evidence references from finding evidence
    evidence_refs = _build_evidence_refs(finding)

    draft = ReportDraft(
        hunt_id=hunt_id,
        finding_id=finding_id,
        title=title,
        severity=cvss.severity,
        cvss_score=cvss.score,
        cvss_vector=cvss.vector,
        summary=summary,
        steps=steps,
        impact=impact,
        remediation=remediation,
        request_ids=request_ids,
        evidence_refs=evidence_refs,
        status=ReportStatus.DRAFT,
    )

    # Persist
    draft.id = context.upsert_report(
        hunt_id,
        {
            "finding_id": finding_id,
            "title": title,
            "severity": cvss.severity.value,
            "cvss_score": cvss.score,
            "cvss_vector": cvss.vector,
            "summary": summary,
            "steps": steps,
            "impact": impact,
            "remediation": remediation,
            "request_ids": request_ids,
            "status": "draft",
        },
    )

    return draft


def draft_chain_report(
    context: HuntContext,
    hunt_id: str,
    chain_id: int,
) -> ReportDraft:
    """Generate a report for an attack chain.

    Merges evidence from all chained findings into a single report.
    """
    chain = context.get_chain(chain_id)
    if not chain:
        raise ValueError(f"Chain {chain_id} not found")

    title = chain["title"]
    severity_str = chain.get("severity", "info")
    cvss_score = chain.get("cvss_score", 0.0)
    cvss_vector = chain.get("cvss_vector", "")
    impact = chain.get("impact", "")

    # Merge steps from all chained findings
    finding_ids = chain.get("chain_order", []) or chain.get("finding_ids", [])
    all_steps: list[str] = []
    all_request_ids: list[int] = []

    for i, fid in enumerate(finding_ids, 1):
        finding = context.get_finding_by_id(fid)
        if not finding:
            continue
        ftype = finding.get("finding_type", "unknown")
        url = finding.get("url", "")
        all_steps.append(f"Step {i}: Exploit {ftype.upper()} on {url}")

        evidence = finding.get("evidence")
        if isinstance(evidence, list):
            for ev in evidence:
                if isinstance(ev, dict):
                    detail = ev.get("note") or ev.get("payload") or ev.get("type", "")
                    if detail:
                        all_steps.append(f"  - Evidence: {detail}")

        rids = finding.get("request_ids", [])
        if isinstance(rids, list):
            all_request_ids.extend(rids)

    summary = (
        f"This report describes a vulnerability chain involving {len(finding_ids)} findings "
        f"that combine to produce {severity_str}-severity impact. {impact}"
    )

    remediation = "Address each vulnerability in the chain individually to break the attack path."

    draft = ReportDraft(
        hunt_id=hunt_id,
        chain_id=chain_id,
        title=title,
        severity=Severity(severity_str),
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        summary=summary,
        steps=all_steps,
        impact=impact,
        remediation=remediation,
        request_ids=all_request_ids,
        status=ReportStatus.DRAFT,
    )

    draft.id = context.upsert_report(
        hunt_id,
        {
            "chain_id": chain_id,
            "title": title,
            "severity": severity_str,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "summary": summary,
            "steps": all_steps,
            "impact": impact,
            "remediation": remediation,
            "request_ids": all_request_ids,
            "status": "draft",
        },
    )

    return draft


# ═══════════════════ Helpers ═══════════════════


def _extract_component(url: str) -> str:
    """Extract a readable component name from a URL."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    if path:
        parts = [p for p in path.split("/") if p]
        return "/".join(parts[:2]) if parts else parsed.hostname or "Application"
    return parsed.hostname or "Application"


def _build_title(ftype: str, component: str, param: str) -> str:
    """Build report title: [Component] [Vuln Type] leads to [Impact]."""
    type_names = {
        "idor": "Insecure Direct Object Reference",
        "ssrf": "Server-Side Request Forgery",
        "xss": "Cross-Site Scripting",
        "sqli": "SQL Injection",
        "auth": "Authentication Bypass",
        "http": "Vulnerability",
    }
    vuln_name = type_names.get(ftype, ftype.upper())
    impact_map = {
        "idor": "Unauthorized Data Access",
        "ssrf": "Internal Network Access",
        "xss": "Client-Side Code Execution",
        "sqli": "Database Compromise",
        "auth": "Unauthorized Access",
    }
    impact = impact_map.get(ftype, "Security Impact")
    param_note = f" via `{param}` Parameter" if param else ""
    return f"{component} — {vuln_name}{param_note} Leads to {impact}"


def _build_summary(finding: dict, ftype: str, url: str, param: str) -> str:
    """Build 2-3 sentence summary."""
    desc = finding.get("description", "")
    if desc:
        return desc
    return (
        f"A {ftype.upper()} vulnerability was identified at {url}"
        f"{f' in the {param} parameter' if param else ''}. "
        f"This allows an attacker to exploit the application's {ftype} weakness."
    )


def _build_steps(context: HuntContext, finding: dict) -> list[str]:
    """Build reproduction steps from evidence and HTTP history."""
    steps: list[str] = []
    url = finding.get("url", "")
    ftype = finding.get("finding_type", "")

    steps.append(f"Navigate to {url}")

    evidence = finding.get("evidence")
    if isinstance(evidence, list):
        for ev in evidence:
            if isinstance(ev, dict):
                payload = ev.get("payload")
                if payload:
                    steps.append(f"Inject payload: {payload}")
                note = ev.get("note")
                if note:
                    steps.append(f"Observe: {note}")

    # Include HTTP request details from history
    request_ids = finding.get("request_ids", [])
    if isinstance(request_ids, list):
        for rid in request_ids[:5]:  # Limit to first 5 requests
            record = context.get_http_record(rid)
            if record:
                method = record.get("method", "GET")
                req_url = record.get("url", "")
                status = record.get("status_code", "?")
                steps.append(f"Send {method} {req_url} → HTTP {status}")

    if not steps or len(steps) == 1:
        steps.append(f"Test the {ftype} vulnerability as described in the evidence")

    steps.append("Observe the vulnerability is exploitable as described above")
    return steps


def _build_impact(finding: dict, ftype: str) -> str:
    """Build concrete impact statement."""
    impact_templates = {
        "idor": "An authenticated attacker can access or modify other users' data "
        "by manipulating object references. This could lead to mass data exfiltration.",
        "ssrf": "An attacker can force the server to make requests to internal resources, "
        "potentially accessing cloud metadata, internal APIs, or sensitive services.",
        "xss": "An attacker can execute arbitrary JavaScript in victims' browsers, "
        "potentially stealing session cookies, credentials, or performing actions on their behalf.",
        "sqli": "An attacker can read, modify, or delete database contents. "
        "Depending on the database configuration, this may escalate to remote code execution.",
        "auth": "An attacker can access protected resources without proper authentication, "
        "potentially gaining administrative access to the application.",
    }
    return impact_templates.get(ftype, finding.get("description", "Security impact identified."))


def _build_evidence_refs(finding: dict) -> list[str]:
    """Extract evidence references from finding evidence array."""
    refs: list[str] = []
    evidence = finding.get("evidence")
    if not isinstance(evidence, list):
        return refs
    for ev in evidence:
        if not isinstance(ev, dict):
            continue
        note = ev.get("note")
        if note and note not in refs:
            refs.append(note)
    return refs
