"""Attack path prioritization — rank untested endpoints by vulnerability likelihood."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse, urlunparse

from boba.core.context import HuntContext


# Patterns that suggest higher vulnerability likelihood
_AUTH_PATTERNS = re.compile(
    r"/(login|logout|auth|signin|signup|register|reset|password|forgot|verify|"
    r"oauth|callback|token|session|sso)",
    re.IGNORECASE,
)
_API_PATTERNS = re.compile(r"/(api|graphql|rest|v\d+)/", re.IGNORECASE)
_UPLOAD_PATTERNS = re.compile(r"/(upload|import|file|media|attachment)", re.IGNORECASE)
_PROXY_PATTERNS = re.compile(r"/(proxy|fetch|redirect|url|webhook|callback|ssrf)", re.IGNORECASE)
_ADMIN_PATTERNS = re.compile(r"/(admin|manage|dashboard|internal|config|settings)", re.IGNORECASE)


def prioritize_endpoints(
    context: HuntContext,
    hunt_id: str,
    top: int | None = None,
) -> list[dict[str, Any]]:
    """Rank untested endpoints by likelihood of containing vulnerabilities.

    Scoring signals:
    - Has query parameters (higher for IDOR, XSS, SQLi)
    - Is an API endpoint (/api/, /v1/)
    - Handles auth operations (login, reset, OAuth)
    - On a host where other vulns were found ("hot host")
    - Handles file uploads or proxying (SSRF risk)
    - Is an admin endpoint (privilege escalation)

    Returns list of {url, method, priority_score, suggested_tests, reasons}.
    """
    # Gather known endpoints
    urls = context.get_urls(hunt_id)
    directories = context.get_directories(hunt_id)
    parameters = context.get_parameters(hunt_id)

    # Build endpoint set with dedup
    endpoints: dict[str, dict[str, Any]] = {}
    for u in urls:
        key = u["url"]
        endpoints[key] = {"url": key, "method": u.get("method", "GET")}
    for d in directories:
        key = d["url"]
        if key not in endpoints:
            endpoints[key] = {"url": key, "method": "GET"}

    if not endpoints:
        return []

    params_by_endpoint: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for param in parameters:
        key = _endpoint_key(param.get("url", ""), param.get("method", "GET"))
        params_by_endpoint.setdefault(key, []).append(param)

    # Get already-tested URLs for exclusion
    coverage = context.get_coverage(hunt_id)
    tested_urls = {r["url"] for r in coverage}

    # Get "hot hosts" — hosts where findings exist
    findings = context.get_findings(hunt_id)
    hot_hosts: set[str] = set()
    for f in findings:
        url = f.get("url")
        if url:
            host = _extract_host(url)
            if host:
                hot_hosts.add(host)

    # Score each untested endpoint
    results: list[dict[str, Any]] = []

    for ep in endpoints.values():
        url = ep["url"]

        # Skip already-tested
        if url in tested_urls:
            continue

        score = 0.0
        reasons: list[str] = []
        suggested: list[str] = []

        # Parse URL for signals
        parsed = urlparse(url)
        path = parsed.path or ""
        query = parsed.query or ""
        host = parsed.hostname or ""
        endpoint_params = params_by_endpoint.get(_endpoint_key(url, ep["method"]), [])

        # Signal: has query parameters
        params = parse_qs(query, keep_blank_values=True)
        if params:
            score += 3.0
            reasons.append(f"Has {len(params)} parameter(s)")
            suggested.extend(["xss", "sqli", "idor"])

        # Signal: hidden parameters discovered by Arjun
        if endpoint_params:
            score += 2.0
            reasons.append(f"Arjun found {len(endpoint_params)} parameter(s)")
            suggested.extend(["xss", "sqli", "idor"])
            confirmed_count = sum(1 for p in endpoint_params if p.get("confirmed"))
            if confirmed_count:
                score += 1.0
                reasons.append(f"{confirmed_count} parameter(s) confirmed by response change")
            if ep["method"].upper() in {"POST", "PUT", "PATCH"} and any(
                p.get("param_type") == "body" for p in endpoint_params
            ):
                suggested.append("mass_assign")

        # Signal: API endpoint
        if _API_PATTERNS.search(path):
            score += 2.0
            reasons.append("API endpoint")
            if "idor" not in suggested:
                suggested.append("idor")

        # Signal: auth-related
        if _AUTH_PATTERNS.search(path):
            score += 3.0
            reasons.append("Auth-related endpoint")
            suggested.append("auth")

        # Signal: admin endpoint
        if _ADMIN_PATTERNS.search(path):
            score += 2.5
            reasons.append("Admin endpoint")
            if "auth" not in suggested:
                suggested.append("auth")

        # Signal: proxy/redirect (SSRF risk)
        if _PROXY_PATTERNS.search(path):
            score += 3.0
            reasons.append("Proxy/redirect endpoint (SSRF risk)")
            suggested.append("ssrf")

        # Signal: file upload
        if _UPLOAD_PATTERNS.search(path):
            score += 2.0
            reasons.append("File handling endpoint")

        # Signal: hot host
        if host in hot_hosts:
            score += 2.0
            reasons.append(f"Host {host} has existing findings")

        # Minimum score for any untested endpoint
        if score == 0:
            score = 1.0
            reasons.append("Untested endpoint")
            suggested.extend(["xss", "sqli"])

        # Deduplicate suggested tests
        seen: set[str] = set()
        unique_suggested = []
        for s in suggested:
            if s not in seen:
                seen.add(s)
                unique_suggested.append(s)

        results.append(
            {
                "url": url,
                "method": ep["method"],
                "priority_score": round(score, 1),
                "suggested_tests": unique_suggested,
                "reasons": reasons,
            }
        )

    # Sort by priority descending
    results.sort(key=lambda x: x["priority_score"], reverse=True)

    if top:
        results = results[:top]

    return results


def _extract_host(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _endpoint_key(url: str, method: str = "GET") -> tuple[str, str]:
    try:
        parsed = urlparse(url)
        normalized = urlunparse(parsed._replace(query="", fragment=""))
    except Exception:
        normalized = url
    return (method or "GET").upper(), normalized
