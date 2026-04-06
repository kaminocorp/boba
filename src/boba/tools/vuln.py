"""Vulnerability testing tools — compose interaction primitives into automated checks."""

from __future__ import annotations

import asyncio
import json as _json_mod
import logging
from typing import Any
import re
from html import unescape as html_unescape
from urllib.parse import quote, unquote, urlencode, urlparse, parse_qs, urlunparse

from boba.core.context import HuntContext
from boba.core.models import (
    Confidence,
    HttpResponse,
    Severity,
    SessionState,
    VulnTestResult,
)
from boba.interaction.http import HttpClient
from boba.interaction.oob import OOBManager
from boba.payloads import ai as ai_payloads
from boba.payloads import auth as auth_payloads
from boba.payloads import csrf as csrf_payloads
from boba.payloads import redirect as redirect_payloads
from boba.payloads import sqli as sqli_payloads
from boba.payloads import ssrf as ssrf_payloads
from boba.payloads import xss as xss_payloads

logger = logging.getLogger(__name__)

# Pre-compiled regex for admin-like endpoint detection (path-boundary matching)
_ADMIN_RE = re.compile(r"/(admin|manage|internal|superuser)([/?#]|$)", re.IGNORECASE)

# Regex matching JSON structural-only lines (braces, brackets, commas)
_JSON_STRUCTURAL_RE = re.compile(rb"^\s*[\[\]{},]*\s*$")

_WAF_STATUS_CODES = frozenset({403, 406, 429, 503})
_AI_CRED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in ai_payloads.CREDENTIAL_PATTERNS]
_WAF_BODY_SIGNATURES = (
    "blocked",
    "waf",
    "firewall",
    "cloudflare",
    "akamai",
    "incapsula",
    "sucuri",
    "mod_security",
    "request blocked",
    "security policy",
)


def _inject_param(url: str, param_name: str, value: str) -> str:
    """Inject a parameter into a URL with proper encoding.

    Preserves existing query parameters and encodes the value correctly,
    preventing payload characters like & # = from breaking URL structure.
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    existing_params = parse_qs(parsed.query, keep_blank_values=True)
    # Flatten: parse_qs returns lists, we want the last value
    flat = {k: v[-1] for k, v in existing_params.items()}
    flat[param_name] = value
    new_query = urlencode(flat, quote_via=quote)
    return urlunparse(parsed._replace(query=new_query))


def _record_coverage(
    context: HuntContext | None,
    hunt_id: str,
    url: str,
    method: str,
    parameter: str,
    test_type: str,
    tool_run_id: int | None = None,
    finding_id: int | None = None,
) -> None:
    """Auto-record a coverage entry after a vuln test completes."""
    if not context or not hunt_id:
        return
    try:
        context.upsert_coverage(
            hunt_id,
            {
                "url": url,
                "method": method,
                "parameter": parameter,
                "test_type": test_type,
                "tool_run_id": tool_run_id,
                "finding_id": finding_id,
            },
        )
    except Exception as exc:
        logger.warning("Failed to record coverage for %s %s: %s", test_type, url, exc)


def _persist_finding(
    context: HuntContext | None,
    hunt_id: str,
    result: VulnTestResult,
    url: str,
    method: str = "GET",
    parameter: str = "",
) -> int | None:
    """Persist a positive VulnTestResult as a finding. Returns finding ID or None."""
    if not context or not hunt_id or not result.vulnerable:
        return None
    try:
        return context.upsert_finding(
            hunt_id,
            {
                "finding_type": result.test_type,
                "severity": result.severity.value,
                "title": result.title,
                "description": result.description,
                "url": url,
                "method": method,
                "parameter": parameter,
                "evidence": result.evidence,
                "request_ids": result.request_ids,
                "confirmed": result.confidence == Confidence.CONFIRMED,
            },
        )
    except Exception as exc:
        logger.error("Finding detected but NOT persisted for %s %s: %s", result.test_type, url, exc)
        return None


async def test_idor(
    http_client: HttpClient,
    session_a: SessionState,
    session_b: SessionState,
    endpoint: str,
    method: str = "GET",
    body: str | None = None,
    object_ids: list[str] | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
) -> VulnTestResult:
    """Test for Insecure Direct Object Reference (IDOR).

    1. Request endpoint as User A (owner) → response_a
    2. Request same endpoint as User B (attacker) → response_b
    3. Request with no auth → response_unauth
    4. Compare: if response_b ≈ response_a AND response_b ≠ response_unauth → IDOR
    """
    # Scope check at function entry — reject out-of-scope endpoints
    if scope_engine and not scope_engine.is_in_scope(endpoint):
        return VulnTestResult(
            test_type="idor",
            vulnerable=False,
            title=f"IDOR on {endpoint}",
            description=f"Skipped: {endpoint} is out of scope",
        )

    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []

    # Request as User A (owner)
    resp_a = await http_client.request(
        method=method,
        url=endpoint,
        headers=session_a.headers,
        cookies=session_a.cookies,
        body=body,
        source="test_idor",
        session_name=session_a.name,
        tags=["idor", "user_a"],
    )
    request_ids.append(resp_a.request_id)
    collected_responses.append(resp_a)

    # Request as User B (attacker)
    resp_b = await http_client.request(
        method=method,
        url=endpoint,
        headers=session_b.headers,
        cookies=session_b.cookies,
        body=body,
        source="test_idor",
        session_name=session_b.name,
        tags=["idor", "user_b"],
    )
    request_ids.append(resp_b.request_id)
    collected_responses.append(resp_b)

    # Request with no auth
    resp_unauth = await http_client.request(
        method=method,
        url=endpoint,
        body=body,
        source="test_idor",
        tags=["idor", "no_auth"],
    )
    request_ids.append(resp_unauth.request_id)
    collected_responses.append(resp_unauth)

    # Analyze
    vulnerable = False
    confidence = Confidence.POSSIBLE
    description = ""

    a_success = 200 <= resp_a.status_code < 400
    b_success = 200 <= resp_b.status_code < 400
    unauth_denied = resp_unauth.status_code in (401, 403)

    if b_success and a_success and unauth_denied:
        # User B can access User A's resource, but unauthenticated cannot.
        # Compare bodies to guard against shared endpoints (e.g. /api/me)
        # where both users get 200 but with their own data.
        body_similar = _bodies_similar(resp_a.body, resp_b.body)
        if body_similar:
            vulnerable = True
            confidence = Confidence.CONFIRMED
            description = (
                f"User B ({session_b.name}) received {resp_b.status_code} for {endpoint} "
                f"with similar body to User A ({resp_a.status_code}), "
                f"while unauthenticated got {resp_unauth.status_code}. "
                "This indicates broken access control."
            )
        else:
            # Bodies differ — this is expected for per-user endpoints (e.g. /api/me)
            # where each user gets their own data. Not a strong IDOR signal.
            vulnerable = False
            confidence = Confidence.POSSIBLE
            description = (
                f"User B ({session_b.name}) received {resp_b.status_code} for {endpoint}, "
                f"same as User A ({resp_a.status_code}), "
                f"while unauthenticated got {resp_unauth.status_code}. "
                "Bodies differ — likely a per-user endpoint, not broken access control."
            )
    elif b_success and a_success:
        # Both succeed — could be public endpoint or IDOR
        body_similar = _bodies_similar(resp_a.body, resp_b.body)
        if body_similar:
            vulnerable = True
            confidence = Confidence.LIKELY
            description = (
                f"Both users received similar {resp_b.status_code} responses for {endpoint}. "
                "The endpoint may be intentionally public or may have broken access control."
            )

    evidence.append(
        {
            "user_a_status": resp_a.status_code,
            "user_b_status": resp_b.status_code,
            "unauth_status": resp_unauth.status_code,
            "body_length_a": len(resp_a.body),
            "body_length_b": len(resp_b.body),
            "body_length_unauth": len(resp_unauth.body),
        }
    )

    # Test additional object IDs if provided (run regardless of confidence
    # to gather enumeration evidence that can upgrade a POSSIBLE to CONFIRMED)
    if object_ids:
        for obj_id in object_ids:
            # Replace the last path segment with the new object ID
            parsed_ep = urlparse(endpoint)
            path_parts = parsed_ep.path.rstrip("/").split("/")
            path_parts[-1] = obj_id
            test_url = urlunparse(parsed_ep._replace(path="/".join(path_parts)))
            # Scope check: verify the constructed URL is still in scope
            if scope_engine and not scope_engine.is_in_scope(test_url):
                continue
            resp = await http_client.request(
                method=method,
                url=test_url,
                headers=session_b.headers,
                cookies=session_b.cookies,
                source="test_idor",
                session_name=session_b.name,
                tags=["idor", "enum"],
            )
            request_ids.append(resp.request_id)
            collected_responses.append(resp)
            if 200 <= resp.status_code < 400:
                # Verify this returns real data, not just a generic success page,
                # by comparing with User A's response.
                enum_body_similar = _bodies_similar(resp_a.body, resp.body)
                evidence.append(
                    {
                        "enumerated_id": obj_id,
                        "status": resp.status_code,
                        "body_similar_to_owner": enum_body_similar,
                    }
                )
                if enum_body_similar and not vulnerable:
                    vulnerable = True
                    confidence = Confidence.LIKELY
                    description = (
                        f"User B ({session_b.name}) can enumerate object IDs on {endpoint} "
                        f"and receives data similar to the owner's response."
                    )

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="idor",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"IDOR on {endpoint}",
        description=description,
        severity=Severity.HIGH if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=["Implement proper authorization checks per-resource"]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    _persist_finding(context, hunt_id, result, endpoint, method)
    _record_coverage(context, hunt_id, endpoint, method, "", "idor")
    return result


async def test_ssrf(
    http_client: HttpClient,
    url: str,
    method: str = "GET",
    injection_points: list[dict] | None = None,
    payloads: list[str] | None = None,
    session: SessionState | None = None,
    oob_manager: OOBManager | None = None,
    poll_timeout_seconds: int = 10,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
    max_test_seconds: float = 300,
) -> VulnTestResult:
    """Test for Server-Side Request Forgery (SSRF).

    Injects internal URLs and OOB callbacks into parameters.

    max_test_seconds caps total wall-clock time to prevent hangs on slow targets.
    """
    if scope_engine and not scope_engine.is_in_scope(url):
        return VulnTestResult(
            test_type="ssrf",
            vulnerable=False,
            title=f"SSRF on {url}",
            description=f"Skipped: {url} is out of scope",
        )
    payloads = payloads or ssrf_payloads.ALL
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []
    headers = session.headers if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE
    _deadline = asyncio.get_running_loop().time() + max_test_seconds

    # Default injection: replace param values in URL
    if not injection_points:
        injection_points = [{"location": "url_param", "name": "url"}]

    for point in injection_points:
        if asyncio.get_running_loop().time() > _deadline:
            logger.warning("test_ssrf timed out after %.0fs on %s", max_test_seconds, url)
            break
        param_name = point.get("name", "url")

        for payload in payloads:
            # Build the request with injected payload (properly URL-encoded)
            test_url = _inject_param(url, param_name, payload)

            resp = await http_client.request(
                method=method,
                url=test_url,
                headers=headers,
                cookies=cookies,
                source="test_ssrf",
                tags=["ssrf", param_name],
            )
            request_ids.append(resp.request_id)
            collected_responses.append(resp)

            # Check for strong SSRF indicators in response (content that could
            # only appear if the server fetched an internal resource).
            # Use context-aware regex to reduce false positives from
            # product names or error messages containing indicator substrings.
            # Patterns require structural context to avoid false positives from
            # error messages (e.g. "root cause" matching "root:").
            ssrf_indicator_patterns = [
                (r"root:[^:]*:\d+:\d+:[^:]*:[^:]*:", "passwd_entry"),  # Full /etc/passwd line
                (r"/bin/(ba)?sh\b", "shell_path"),  # Shell binary path (word boundary)
                (r"ami-[0-9a-f]{8,}", "aws_ami_id"),  # AWS AMI ID (min 8 hex chars)
                (r'"instanceId"\s*:', "aws_instance"),  # AWS JSON metadata field
                (r"computeMetadata/v\d", "gcp_metadata"),  # GCP metadata path with version
            ]
            for pattern, indicator_type in ssrf_indicator_patterns:
                if re.search(pattern, resp.body_text, re.IGNORECASE):
                    vulnerable = True
                    confidence = Confidence.CONFIRMED
                    evidence.append(
                        {
                            "payload": payload,
                            "param": param_name,
                            "indicator": indicator_type,
                            "status_code": resp.status_code,
                            "request_id": resp.request_id,
                        }
                    )
                    break

            # Cloud metadata 200 check — require metadata-like body content
            # to reduce false positives from generic 200 error/WAF pages
            if resp.status_code == 200 and "169.254.169.254" in payload:
                body_lower = resp.body_text.lower()
                metadata_signals = (
                    "ami-id",
                    "instance-id",
                    "iam",
                    "security-credentials",
                    "hostname",
                    "local-ipv4",
                    "public-ipv4",
                    "meta-data",
                    "computeMetadata",
                    "instance/",
                    "project/",
                )
                has_metadata_content = any(sig.lower() in body_lower for sig in metadata_signals)
                if has_metadata_content:
                    if not vulnerable:
                        vulnerable = True
                        confidence = Confidence.LIKELY
                    evidence.append(
                        {
                            "payload": payload,
                            "param": param_name,
                            "note": "200 response with metadata-like content for cloud metadata URL",
                            "request_id": resp.request_id,
                        }
                    )

            # Stop testing this injection point once confirmed
            if confidence == Confidence.CONFIRMED:
                break
        if confidence == Confidence.CONFIRMED:
            break

    # OOB detection for blind SSRF
    if oob_manager and not vulnerable:
        for point in injection_points:
            param_name = point.get("name", "url")
            callback = await oob_manager.create_listener(
                purpose="blind_ssrf",
                target_url=url,
                parameter=param_name,
            )
            oob_url = oob_manager.get_payload_url(callback)

            test_url = _inject_param(url, param_name, oob_url)

            resp = await http_client.request(
                method=method,
                url=test_url,
                headers=headers,
                cookies=cookies,
                source="test_ssrf",
                tags=["ssrf", "blind"],
            )
            request_ids.append(resp.request_id)
            collected_responses.append(resp)

        # Poll for callbacks
        interactions = await oob_manager.poll(timeout_seconds=poll_timeout_seconds)
        if interactions:
            vulnerable = True
            confidence = Confidence.CONFIRMED
            for i in interactions:
                evidence.append(
                    {
                        "type": "oob_callback",
                        "listener_id": i.get("listener_id"),
                        "purpose": i.get("purpose"),
                        "target_url": i.get("target_url"),
                        "parameter": i.get("parameter"),
                        "interaction": i,
                    }
                )

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="ssrf",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"SSRF on {url}",
        description="Server-side request forgery detected" if vulnerable else "",
        severity=Severity.CRITICAL if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=["Validate and whitelist URLs server-side", "Block internal IPs"]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    param_name = injection_points[0].get("name", "url") if injection_points else "url"
    _persist_finding(context, hunt_id, result, url, method, param_name)
    _record_coverage(context, hunt_id, url, method, param_name, "ssrf")
    return result


async def test_xss(
    http_client: HttpClient,
    url: str,
    method: str = "GET",
    params: dict[str, str] | None = None,
    payloads: list[str] | None = None,
    session: SessionState | None = None,
    check_dom: bool = False,
    browser: Any = None,
    oob_manager: OOBManager | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
    max_test_seconds: float = 300,
) -> VulnTestResult:
    """Test for Cross-Site Scripting (XSS).

    1. Reflected: inject payloads, check if they appear unescaped in response
    2. DOM-based: render in browser, check if canary JS executes
    3. Blind: inject OOB callback payloads

    max_test_seconds caps total wall-clock time to prevent hangs on slow targets.
    """
    if scope_engine and not scope_engine.is_in_scope(url):
        return VulnTestResult(
            test_type="xss",
            vulnerable=False,
            title=f"XSS on {url}",
            description=f"Skipped: {url} is out of scope",
        )
    payloads = payloads or xss_payloads.BASIC
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []
    headers = session.headers if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE

    test_params = params or {"q": ""}
    _deadline = asyncio.get_running_loop().time() + max_test_seconds

    for param_name in test_params:
        if asyncio.get_running_loop().time() > _deadline:
            logger.warning("test_xss timed out after %.0fs on %s", max_test_seconds, url)
            break
        for payload in payloads:
            # Build URL with injected payload (properly URL-encoded)
            test_url = _inject_param(url, param_name, payload)

            resp = await http_client.request(
                method=method,
                url=test_url,
                headers=headers,
                cookies=cookies,
                source="test_xss",
                tags=["xss", param_name],
            )
            request_ids.append(resp.request_id)
            collected_responses.append(resp)

            # Check reflection — payload appears unescaped in response.
            # Also check the URL-decoded form for encoding bypass payloads
            # (servers typically decode parameters before reflecting).
            decoded_payload = unquote(payload)
            if payload in resp.body_text:
                vulnerable = True
                confidence = Confidence.CONFIRMED
                evidence.append(
                    {
                        "type": "reflected",
                        "payload": payload,
                        "param": param_name,
                        "request_id": resp.request_id,
                    }
                )
                break  # Found confirmed XSS for this param

            if decoded_payload != payload and decoded_payload in resp.body_text:
                vulnerable = True
                confidence = Confidence.CONFIRMED
                evidence.append(
                    {
                        "type": "reflected_decoded",
                        "payload": payload,
                        "decoded": decoded_payload,
                        "param": param_name,
                        "request_id": resp.request_id,
                    }
                )
                break

            # Check for HTML-entity-encoded reflection (e.g. <script> → &lt;script&gt;)
            html_decoded = html_unescape(resp.body_text)
            if html_decoded != resp.body_text and payload in html_decoded:
                # Payload present after HTML entity decoding — server is encoding
                # output, which is actually a defense. Mark as POSSIBLE, not CONFIRMED.
                evidence.append(
                    {
                        "type": "reflected_html_encoded",
                        "payload": payload,
                        "param": param_name,
                        "note": "Payload reflected with HTML entity encoding (output is escaped)",
                        "request_id": resp.request_id,
                    }
                )
                # Don't set vulnerable=True — entity encoding is a mitigation.
                # But track it as evidence for potential bypass analysis.

            # Check for partial reflection: extract inner content between tags
            # e.g. "<script>alert(1)</script>" → check for "alert(1)"
            # Require 16+ chars AND JS-specific patterns to reduce false positives
            inner = re.sub(r"<[^>]*>", "", payload).strip()
            has_js_context = bool(
                re.search(r"(on\w+=|javascript:|alert\(|prompt\(|confirm\()", inner, re.I)
            )
            if inner and len(inner) >= 16 and has_js_context and inner in resp.body_text:
                vulnerable = True
                confidence = Confidence.POSSIBLE
                evidence.append(
                    {
                        "type": "partial_reflection",
                        "payload": payload,
                        "param": param_name,
                        "note": f"Inner content '{inner}' reflected without tags",
                        "request_id": resp.request_id,
                    }
                )

    # DOM-based XSS check via browser (runs for all params, even if reflected was found,
    # because DOM-based XSS on param B is a distinct finding from reflected on param A).
    if check_dom and browser:
        dom_found = False
        for param_name in test_params:
            for canary in xss_payloads.DOM_CANARY:
                test_url = _inject_param(url, param_name, canary)
                await browser.navigate(test_url)
                # Check both canary flag and error-based detection (CSP may block
                # window property assignment but allow error-based signals)
                fired = await browser.execute_js(
                    "() => window.__xss_fired === true || "
                    "document.querySelector('img[src*=\"xss\"]') !== null"
                )
                if fired:
                    vulnerable = True
                    dom_found = True
                    confidence = Confidence.CONFIRMED
                    evidence.append(
                        {
                            "type": "dom_based",
                            "payload": canary,
                            "param": param_name,
                            "url": test_url,
                        }
                    )
                    break
            if dom_found:
                break

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="xss",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"XSS on {url}",
        description="Cross-site scripting via parameter injection" if vulnerable else "",
        severity=Severity.MEDIUM if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=["Encode output contextually", "Implement Content-Security-Policy"]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    param_str = ",".join(test_params.keys())
    _persist_finding(context, hunt_id, result, url, method, param_str)
    for pname in test_params:
        _record_coverage(context, hunt_id, url, method, pname, "xss")
    return result


async def test_sqli(
    http_client: HttpClient,
    url: str,
    method: str = "GET",
    params: dict[str, str] | None = None,
    session: SessionState | None = None,
    payloads: list[str] | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
    max_test_seconds: float = 300,
) -> VulnTestResult:
    """Test for SQL injection.

    1. Baseline: normal request
    2. Error-based: inject ' " ) → check for SQL error strings
    3. Boolean-based: true vs false conditions → compare response lengths
    4. Time-based: SLEEP payloads → check response time delta (≥3s over baseline)

    max_test_seconds caps total wall-clock time to prevent hangs on slow targets.
    """
    if scope_engine and not scope_engine.is_in_scope(url):
        return VulnTestResult(
            test_type="sqli",
            vulnerable=False,
            title=f"SQL Injection on {url}",
            description=f"Skipped: {url} is out of scope",
        )
    payloads = payloads or sqli_payloads.ERROR_BASED
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []
    headers = session.headers if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE

    test_params = params or {"id": "1"}
    _deadline = asyncio.get_running_loop().time() + max_test_seconds

    for param_name, default_val in test_params.items():
        if asyncio.get_running_loop().time() > _deadline:
            logger.warning("test_sqli timed out after %.0fs on %s", max_test_seconds, url)
            break
        # Baseline: request with the normal parameter value, so true/false comparisons
        # are against the same endpoint shape (not the bare URL without the param).
        baseline_url = _inject_param(url, param_name, default_val)
        resp_baseline = await http_client.request(
            method=method,
            url=baseline_url,
            headers=headers,
            cookies=cookies,
            source="test_sqli",
            tags=["sqli", "baseline"],
        )
        request_ids.append(resp_baseline.request_id)
        # Error-based detection
        for payload in payloads:
            test_url = _inject_param(url, param_name, f"{default_val}{payload}")

            resp = await http_client.request(
                method=method,
                url=test_url,
                headers=headers,
                cookies=cookies,
                source="test_sqli",
                tags=["sqli", "error_based"],
            )
            request_ids.append(resp.request_id)
            collected_responses.append(resp)

            # Check for SQL error signatures in response
            body_lower = resp.body_text.lower()
            for sig in sqli_payloads.ERROR_SIGNATURES:
                if sig.lower() in body_lower:
                    vulnerable = True
                    confidence = Confidence.CONFIRMED
                    evidence.append(
                        {
                            "type": "error_based",
                            "payload": payload,
                            "param": param_name,
                            "error_signature": sig,
                            "request_id": resp.request_id,
                        }
                    )
                    break
            if vulnerable:
                break

        if vulnerable:
            break

        # Boolean-based detection — try multiple payload styles
        # (single-quote string context AND numeric context)
        boolean_pairs = list(
            zip(sqli_payloads.BOOLEAN_BASED[::2], sqli_payloads.BOOLEAN_BASED[1::2])
        )
        for true_payload, false_payload in boolean_pairs:
            resp_true = await http_client.request(
                method=method,
                url=_inject_param(url, param_name, f"{default_val}{true_payload}"),
                headers=headers,
                cookies=cookies,
                source="test_sqli",
                tags=["sqli", "boolean_true"],
            )
            resp_false = await http_client.request(
                method=method,
                url=_inject_param(url, param_name, f"{default_val}{false_payload}"),
                headers=headers,
                cookies=cookies,
                source="test_sqli",
                tags=["sqli", "boolean_false"],
            )
            request_ids.extend([resp_true.request_id, resp_false.request_id])
            collected_responses.extend([resp_true, resp_false])

            # If true/false conditions produce different response lengths, likely SQLi.
            # Guards: (1) true-condition must match baseline, (2) false must NOT.
            len_diff = abs(len(resp_true.body) - len(resp_false.body))
            baseline_len = max(len(resp_baseline.body), 1)
            relative_diff = len_diff / baseline_len
            true_matches_baseline = _bodies_similar(resp_true.body, resp_baseline.body)
            false_matches_baseline = _bodies_similar(resp_false.body, resp_baseline.body)
            if (
                resp_true.status_code == resp_false.status_code
                and (len_diff >= 20 or relative_diff >= 0.05)
                and len_diff > 0
                and resp_true.status_code == resp_baseline.status_code
                and true_matches_baseline
                and not false_matches_baseline
            ):
                vulnerable = True
                confidence = Confidence.LIKELY
                evidence.append(
                    {
                        "type": "boolean_based",
                        "param": param_name,
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "true_length": len(resp_true.body),
                        "false_length": len(resp_false.body),
                        "diff": len_diff,
                    }
                )
                break  # Found boolean SQLi with this payload pair

        # Time-based detection — only if not already confirmed via error/boolean.
        # Uses multiple baseline samples to reduce false positives from network jitter.
        if not vulnerable:
            if asyncio.get_running_loop().time() > _deadline:
                logger.warning("test_sqli timed out before time-based phase on %s", url)
                break
            time_payloads = (
                sqli_payloads.TIME_BASED_MYSQL
                + sqli_payloads.TIME_BASED_POSTGRES
                + sqli_payloads.TIME_BASED_MSSQL
                + sqli_payloads.TIME_BASED_SQLITE
            )
            # Collect multiple baseline timing samples for statistical robustness
            baseline_samples = [resp_baseline.elapsed_ms]
            for _ in range(2):
                resp_bl = await http_client.request(
                    method=method,
                    url=baseline_url,
                    headers=headers,
                    cookies=cookies,
                    source="test_sqli",
                    tags=["sqli", "baseline_timing"],
                )
                request_ids.append(resp_bl.request_id)
                baseline_samples.append(resp_bl.elapsed_ms)
            baseline_median = sorted(baseline_samples)[len(baseline_samples) // 2]

            for payload in time_payloads:
                if asyncio.get_running_loop().time() > _deadline:
                    logger.warning("test_sqli time-based phase timed out on %s", url)
                    break
                test_url = _inject_param(url, param_name, f"{default_val}{payload}")
                resp_time = await http_client.request(
                    method=method,
                    url=test_url,
                    headers=headers,
                    cookies=cookies,
                    source="test_sqli",
                    tags=["sqli", "time_based"],
                    timeout_seconds=15.0,
                )
                request_ids.append(resp_time.request_id)
                collected_responses.append(resp_time)
                # A SLEEP(5) payload should add ≥3s over the median baseline
                delay_ms = resp_time.elapsed_ms - baseline_median
                if delay_ms >= 3000:
                    # Confirmation: re-send the same payload — both must be slow
                    resp_confirm = await http_client.request(
                        method=method,
                        url=test_url,
                        headers=headers,
                        cookies=cookies,
                        source="test_sqli",
                        tags=["sqli", "time_confirm"],
                        timeout_seconds=15.0,
                    )
                    request_ids.append(resp_confirm.request_id)
                    collected_responses.append(resp_confirm)
                    confirm_delay = resp_confirm.elapsed_ms - baseline_median
                    if confirm_delay < 3000:
                        continue  # First hit was a network fluke
                    vulnerable = True
                    confidence = Confidence.LIKELY
                    evidence.append(
                        {
                            "type": "time_based",
                            "payload": payload,
                            "param": param_name,
                            "baseline_median_ms": baseline_median,
                            "response_ms": resp_time.elapsed_ms,
                            "confirm_ms": resp_confirm.elapsed_ms,
                            "delay_ms": delay_ms,
                            "confirm_delay_ms": confirm_delay,
                            "request_id": resp_time.request_id,
                        }
                    )
                    break

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="sqli",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"SQL Injection on {url}",
        description="SQL injection detected via error or boolean-based analysis"
        if vulnerable
        else "",
        severity=Severity.HIGH if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=["Use parameterized queries", "Implement input validation"]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    param_str = ",".join(test_params.keys())
    _persist_finding(context, hunt_id, result, url, method, param_str)
    for pname in test_params:
        _record_coverage(context, hunt_id, url, method, pname, "sqli")
    return result


async def test_auth(
    http_client: HttpClient,
    endpoint: str,
    session: SessionState | None = None,
    jwt_token: str | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
) -> VulnTestResult:
    """Test authentication/authorization controls.

    1. No-auth: request without credentials → should be 401/403
    2. JWT none algorithm: re-sign with alg=none
    3. JWT claim manipulation: modify role/admin claims
    """
    if scope_engine and not scope_engine.is_in_scope(endpoint):
        return VulnTestResult(
            test_type="auth",
            vulnerable=False,
            title=f"Auth bypass on {endpoint}",
            description=f"Skipped: {endpoint} is out of scope",
        )
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []
    vulnerable = False
    confidence = Confidence.POSSIBLE

    # Test 1: No auth → should be denied
    resp_noauth = await http_client.request(
        method="GET",
        url=endpoint,
        source="test_auth",
        tags=["auth", "no_auth"],
    )
    request_ids.append(resp_noauth.request_id)

    if 200 <= resp_noauth.status_code < 400:
        # Only flag as vulnerable if we have a session to compare against
        # (otherwise we can't distinguish public endpoints from broken auth)
        # or if the endpoint looks admin-like.
        if session or _ADMIN_RE.search(endpoint):
            vulnerable = True
            confidence = Confidence.LIKELY if session else Confidence.POSSIBLE
            evidence.append(
                {
                    "type": "no_auth_access",
                    "status_code": resp_noauth.status_code,
                    "note": "Endpoint accessible without any authentication",
                }
            )
        else:
            evidence.append(
                {
                    "type": "no_auth_access",
                    "status_code": resp_noauth.status_code,
                    "note": "Endpoint accessible without auth — may be intentionally public",
                }
            )

    # Test 2: JWT manipulation (if token provided)
    if jwt_token:
        try:
            # None algorithm attack
            none_token = auth_payloads.jwt_none_algorithm(jwt_token)
            resp_none = await http_client.request(
                method="GET",
                url=endpoint,
                headers={"Authorization": f"Bearer {none_token}"},
                source="test_auth",
                tags=["auth", "jwt_none"],
            )
            request_ids.append(resp_none.request_id)
            collected_responses.append(resp_none)

            if 200 <= resp_none.status_code < 400:
                vulnerable = True
                confidence = Confidence.CONFIRMED
                evidence.append(
                    {
                        "type": "jwt_none_algorithm",
                        "status_code": resp_none.status_code,
                        "note": "JWT with alg=none accepted",
                    }
                )

            # Claim escalation
            for claims in auth_payloads.ESCALATION_CLAIMS:
                modified_token = auth_payloads.jwt_modify_claims(jwt_token, claims)
                resp_esc = await http_client.request(
                    method="GET",
                    url=endpoint,
                    headers={"Authorization": f"Bearer {modified_token}"},
                    source="test_auth",
                    tags=["auth", "jwt_escalation"],
                )
                request_ids.append(resp_esc.request_id)
                collected_responses.append(resp_esc)

                if 200 <= resp_esc.status_code < 400:
                    vulnerable = True
                    confidence = Confidence.LIKELY
                    evidence.append(
                        {
                            "type": "jwt_claim_escalation",
                            "modified_claims": claims,
                            "status_code": resp_esc.status_code,
                        }
                    )
                    break

        except (ValueError, KeyError, IndexError) as exc:
            # Invalid JWT format — skip JWT tests
            logger.debug("JWT manipulation skipped for %s: %s", endpoint, exc)

    # Test 3: With valid session — compare authed vs unauthed to confirm no-auth finding
    if session:
        resp_auth = await http_client.request(
            method="GET",
            url=endpoint,
            headers=session.headers,
            cookies=session.cookies,
            source="test_auth",
            session_name=session.name,
            tags=["auth", "session"],
        )
        request_ids.append(resp_auth.request_id)

        if 200 <= resp_auth.status_code < 400:
            # Upgrade no-auth finding if authed response differs from unauthed
            # (meaning the endpoint IS auth-aware but doesn't enforce it)
            if 200 <= resp_noauth.status_code < 400:
                if not _bodies_similar(resp_auth.body, resp_noauth.body):
                    # Different content with vs without auth — endpoint is auth-aware
                    # but still returns 200 without auth = broken auth
                    vulnerable = True
                    confidence = Confidence.CONFIRMED
                    evidence.append(
                        {
                            "type": "auth_aware_but_unenforced",
                            "authed_status": resp_auth.status_code,
                            "unauthed_status": resp_noauth.status_code,
                            "note": "Authed and unauthed responses differ, but endpoint allows unauthenticated access",
                        }
                    )

            # Check if it looks like an admin endpoint
            if _ADMIN_RE.search(endpoint) and not vulnerable:
                vulnerable = True
                confidence = Confidence.LIKELY
                evidence.append(
                    {
                        "type": "privilege_escalation",
                        "endpoint": endpoint,
                        "status_code": resp_auth.status_code,
                        "note": f"User '{session.name}' can access admin-like endpoint",
                    }
                )

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="auth",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"Auth bypass on {endpoint}",
        description="Authentication/authorization control weakness detected" if vulnerable else "",
        severity=Severity.CRITICAL if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=[
            "Enforce authentication on all protected endpoints",
            "Validate JWT signatures server-side",
            "Implement role-based access control",
        ]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    # Determine the most descriptive "parameter" for finding persistence
    auth_param = "jwt" if jwt_token else ""
    _persist_finding(context, hunt_id, result, endpoint, "GET", auth_param)
    _record_coverage(context, hunt_id, endpoint, "GET", auth_param, "auth")
    return result


async def test_race(
    http_client: HttpClient,
    session: SessionState,
    url: str,
    method: str = "POST",
    body: str | None = None,
    concurrency: int = 10,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
) -> VulnTestResult:
    """Test for race conditions via concurrent identical requests.

    Sends `concurrency` identical requests simultaneously and compares responses.
    Divergent responses indicate a potential race condition.
    """
    if scope_engine and not scope_engine.is_in_scope(url):
        return VulnTestResult(
            test_type="race",
            vulnerable=False,
            title=f"Race condition on {url}",
            description=f"Skipped: {url} is out of scope",
        )
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    headers = session.headers if session else {}
    cookies = session.cookies if session else {}

    # Send concurrent requests
    async def _send():
        return await http_client.request(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            body=body,
            source="test_race",
            session_name=session.name,
            tags=["race"],
        )

    results = await asyncio.gather(*[_send() for _ in range(concurrency)], return_exceptions=True)
    responses = [r for r in results if not isinstance(r, BaseException)]
    errors = [r for r in results if isinstance(r, BaseException)]
    if errors:
        logger.warning("Race test: %d/%d requests failed", len(errors), concurrency)
    if not responses:
        return VulnTestResult(
            test_type="race",
            vulnerable=False,
            title="Race condition test failed — all requests errored",
            description=f"All {concurrency} concurrent requests failed.",
            severity=Severity.INFO,
        )
    request_ids = [r.request_id for r in responses]

    # Analyze: check for divergent responses
    status_codes = [r.status_code for r in responses]
    bodies = [r.body for r in responses]
    unique_statuses = set(status_codes)
    unique_bodies = len(set(bodies))

    vulnerable = False
    confidence = Confidence.POSSIBLE

    # Filter out benign status variance: 304 (caching) and 429 (rate limiting)
    # are expected under concurrency and do not indicate a race condition.
    meaningful_statuses = {s for s in status_codes if s not in (304, 429)}
    meaningful_divergence = len(meaningful_statuses) > 1

    if meaningful_divergence:
        vulnerable = True
        confidence = Confidence.LIKELY
        evidence.append(
            {
                "type": "status_divergence",
                "status_codes": status_codes,
                "unique_count": len(meaningful_statuses),
            }
        )
        if unique_bodies > 1:
            # Both status AND body diverge — strongest signal.
            confidence = Confidence.CONFIRMED
            evidence.append(
                {
                    "type": "body_divergence",
                    "unique_bodies": unique_bodies,
                    "total_requests": concurrency,
                }
            )
    elif len(unique_statuses) > 1:
        # Only cache/rate-limit variance — informational, not a vulnerability.
        evidence.append(
            {
                "type": "benign_status_variance",
                "status_codes": status_codes,
                "note": "Only 304/429 variance detected (caching or rate limiting)",
            }
        )
    elif unique_bodies > 1:
        # Body divergence alone is evidence-only (timestamps, CSRF tokens, etc.
        # cause natural variance). Only status divergence confirms a race.
        evidence.append(
            {
                "type": "body_divergence",
                "unique_bodies": unique_bodies,
                "total_requests": concurrency,
            }
        )

    # Multiple successes — informational evidence, not a standalone signal
    # (most endpoints return 200 for all requests regardless of serialization)
    success_count = sum(1 for s in status_codes if 200 <= s < 300)
    if success_count > 1:
        evidence.append(
            {
                "type": "multiple_successes",
                "success_count": success_count,
                "total_requests": concurrency,
            }
        )

    waf_detected = not vulnerable and _detect_waf(responses)
    result = VulnTestResult(
        test_type="race",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"Race condition on {url}",
        description=f"Concurrent requests produced divergent responses ({len(unique_statuses)} status codes, {unique_bodies} unique bodies)"
        if vulnerable
        else "",
        severity=Severity.HIGH if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=[
            "Implement mutex/locking on state-changing operations",
            "Use database-level unique constraints for one-time actions",
        ]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    _persist_finding(context, hunt_id, result, url, method)
    _record_coverage(context, hunt_id, url, method, "", "race")
    return result


async def test_redirect(
    http_client: HttpClient,
    url: str,
    param: str,
    payloads: list[str] | None = None,
    session: SessionState | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
) -> VulnTestResult:
    """Test for open redirect vulnerabilities.

    Injects redirect payloads into the specified parameter and checks if
    the response redirects to an external host.
    """
    if scope_engine and not scope_engine.is_in_scope(url):
        return VulnTestResult(
            test_type="redirect",
            vulnerable=False,
            title=f"Open redirect on {url}",
            description=f"Skipped: {url} is out of scope",
        )
    payloads = payloads or redirect_payloads.ALL
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []
    headers = session.headers if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE

    target_host = urlparse(url).hostname or ""

    for payload in payloads:
        test_url = _inject_param(url, param, payload)

        resp = await http_client.request(
            method="GET",
            url=test_url,
            headers=headers,
            cookies=cookies,
            follow_redirects=False,
            source="test_redirect",
            tags=["redirect", param],
        )
        request_ids.append(resp.request_id)
        collected_responses.append(resp)

        # Check Location header for external redirect
        location = ""
        for k, v in resp.headers.items():
            if k.lower() == "location":
                location = v
                break

        if location and resp.status_code in (301, 302, 303, 307, 308):
            redirect_host = urlparse(location).hostname or ""
            if (
                redirect_host
                and redirect_host != target_host
                and not redirect_host.endswith(f".{target_host}")
            ):
                vulnerable = True
                confidence = Confidence.CONFIRMED
                evidence.append(
                    {
                        "type": "external_redirect",
                        "payload": payload,
                        "param": param,
                        "location": location,
                        "redirect_host": redirect_host,
                        "status_code": resp.status_code,
                        "request_id": resp.request_id,
                    }
                )
                break

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="redirect",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"Open redirect on {url}",
        description=f"Open redirect via {param} parameter to external host" if vulnerable else "",
        severity=Severity.MEDIUM if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=[
            "Validate redirect URLs against an allowlist",
            "Use relative paths instead of full URLs for redirects",
        ]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    _persist_finding(context, hunt_id, result, url, "GET", param)
    _record_coverage(context, hunt_id, url, "GET", param, "redirect")
    return result


async def test_csrf(
    http_client: HttpClient,
    session: SessionState,
    url: str,
    method: str = "POST",
    body: str | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
) -> VulnTestResult:
    """Test for Cross-Site Request Forgery.

    Checks: no CSRF token required, invalid token accepted, cross-origin accepted.
    """
    if scope_engine and not scope_engine.is_in_scope(url):
        return VulnTestResult(
            test_type="csrf",
            vulnerable=False,
            title=f"CSRF on {url}",
            description=f"Skipped: {url} is out of scope",
        )
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []
    headers = dict(session.headers) if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE

    # Test 1: Send request without CSRF token
    # Strip known CSRF headers
    clean_headers = {
        k: v for k, v in headers.items() if k.lower() not in ("x-csrf-token", "x-xsrf-token")
    }
    # Strip known CSRF token params from request body
    clean_body = body
    if clean_body:
        try:
            body_obj = _json_mod.loads(clean_body)
            if isinstance(body_obj, dict):
                token_names_lower = {n.lower() for n in csrf_payloads.TOKEN_PARAM_NAMES}
                body_obj = {k: v for k, v in body_obj.items() if k.lower() not in token_names_lower}
                clean_body = _json_mod.dumps(body_obj)
        except (ValueError, TypeError):
            # Form-encoded body — strip token params
            try:
                params = parse_qs(clean_body, keep_blank_values=True)
                token_names_lower = {n.lower() for n in csrf_payloads.TOKEN_PARAM_NAMES}
                params = {k: v for k, v in params.items() if k.lower() not in token_names_lower}
                clean_body = urlencode(params, doseq=True) if params else ""
            except Exception:
                pass

    resp_no_token = await http_client.request(
        method=method,
        url=url,
        headers=clean_headers,
        cookies=cookies,
        body=clean_body,
        source="test_csrf",
        tags=["csrf", "no_token"],
    )
    request_ids.append(resp_no_token.request_id)
    collected_responses.append(resp_no_token)

    if 200 <= resp_no_token.status_code < 400:
        vulnerable = True
        confidence = Confidence.LIKELY
        evidence.append(
            {
                "type": "no_csrf_token",
                "status_code": resp_no_token.status_code,
                "note": "Request accepted without CSRF token",
            }
        )

    # Test 2: Send with invalid CSRF token
    invalid_headers = dict(clean_headers)
    invalid_headers["X-CSRF-Token"] = "invalid-token-value"

    resp_invalid = await http_client.request(
        method=method,
        url=url,
        headers=invalid_headers,
        cookies=cookies,
        body=clean_body,
        source="test_csrf",
        tags=["csrf", "invalid_token"],
    )
    request_ids.append(resp_invalid.request_id)
    collected_responses.append(resp_invalid)

    if 200 <= resp_invalid.status_code < 400:
        if vulnerable:
            confidence = Confidence.CONFIRMED
        else:
            vulnerable = True
            confidence = Confidence.LIKELY
        evidence.append(
            {
                "type": "invalid_token_accepted",
                "status_code": resp_invalid.status_code,
                "note": "Request accepted with invalid CSRF token",
            }
        )

    # Test 3: Cross-origin request
    cross_origin_headers = dict(clean_headers)
    cross_origin_headers.update(csrf_payloads.CROSS_ORIGIN_HEADERS)

    resp_cross = await http_client.request(
        method=method,
        url=url,
        headers=cross_origin_headers,
        cookies=cookies,
        body=clean_body,
        source="test_csrf",
        tags=["csrf", "cross_origin"],
    )
    request_ids.append(resp_cross.request_id)
    collected_responses.append(resp_cross)

    if 200 <= resp_cross.status_code < 400:
        evidence.append(
            {
                "type": "cross_origin_accepted",
                "status_code": resp_cross.status_code,
                "origin": csrf_payloads.CROSS_ORIGIN_HEADERS.get("Origin", ""),
                "note": "Cross-origin request accepted",
            }
        )

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="csrf",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"CSRF on {url}",
        description="Cross-site request forgery — state-changing request accepted without token validation"
        if vulnerable
        else "",
        severity=Severity.MEDIUM if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=[
            "Implement anti-CSRF tokens on all state-changing endpoints",
            "Set SameSite=Strict on session cookies",
        ]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    _persist_finding(context, hunt_id, result, url, method)
    _record_coverage(context, hunt_id, url, method, "", "csrf")
    return result


async def test_mass_assign(
    http_client: HttpClient,
    session: SessionState,
    url: str,
    method: str = "PUT",
    base_body: dict | None = None,
    extra_fields: dict | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
) -> VulnTestResult:
    """Test for mass assignment / parameter pollution.

    Sends extra fields (isAdmin, role, etc.) and checks if they persist.
    """
    if scope_engine and not scope_engine.is_in_scope(url):
        return VulnTestResult(
            test_type="mass_assign",
            vulnerable=False,
            title=f"Mass assignment on {url}",
            description=f"Skipped: {url} is out of scope",
        )
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []
    headers = dict(session.headers) if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE

    if "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"

    base = base_body or {}
    extras = extra_fields or {
        "isAdmin": True,
        "role": "admin",
        "verified": True,
        "balance": 999999,
        "plan": "enterprise",
    }

    # Step 1: GET baseline
    resp_before = await http_client.request(
        method="GET",
        url=url,
        headers=headers,
        cookies=cookies,
        source="test_mass_assign",
        tags=["mass_assign", "baseline"],
    )
    request_ids.append(resp_before.request_id)
    collected_responses.append(resp_before)

    # Step 2: Send with extra fields
    payload = {**base, **extras}
    resp_update = await http_client.request(
        method=method,
        url=url,
        headers=headers,
        cookies=cookies,
        body=_json_mod.dumps(payload),
        source="test_mass_assign",
        tags=["mass_assign", "inject"],
    )
    request_ids.append(resp_update.request_id)
    collected_responses.append(resp_update)

    # Step 3: GET again to check persistence
    resp_after = await http_client.request(
        method="GET",
        url=url,
        headers=headers,
        cookies=cookies,
        source="test_mass_assign",
        tags=["mass_assign", "verify"],
    )
    request_ids.append(resp_after.request_id)
    collected_responses.append(resp_after)

    # Compare: check if any extra fields appeared in the after response
    try:
        after_data = _json_mod.loads(resp_after.body_text)
        if isinstance(after_data, dict):
            for field, value in extras.items():
                if field in after_data:
                    actual = after_data[field]
                    # Check if it wasn't there before or changed
                    try:
                        before_data = _json_mod.loads(resp_before.body_text)
                    except (ValueError, TypeError):
                        before_data = {}
                    before_val = before_data.get(field) if isinstance(before_data, dict) else None
                    if actual == value and before_val != value:
                        vulnerable = True
                        confidence = Confidence.CONFIRMED
                        evidence.append(
                            {
                                "type": "field_persisted",
                                "field": field,
                                "injected_value": value,
                                "actual_value": actual,
                            }
                        )
    except (ValueError, TypeError) as exc:
        logger.warning(
            "Mass assignment: could not parse response from %s as JSON (%s). "
            "Non-JSON endpoints require manual review.",
            url,
            exc,
        )
        evidence.append(
            {
                "type": "parse_error",
                "note": f"Response is not JSON ({exc}); mass assignment not verifiable",
                "status_code": resp_after.status_code,
            }
        )

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="mass_assign",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"Mass assignment on {url}",
        description="Extra fields persisted via mass assignment" if vulnerable else "",
        severity=Severity.HIGH if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=[
            "Whitelist allowed fields in the API endpoint",
            "Never bind request body directly to model objects",
        ]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    _persist_finding(context, hunt_id, result, url, method)
    _record_coverage(context, hunt_id, url, method, "", "mass_assign")
    return result


async def test_reset(
    http_client: HttpClient,
    url: str,
    email_param: str = "email",
    test_email: str = "test@example.com",
    session: SessionState | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
) -> VulnTestResult:
    """Test password reset flow for vulnerabilities.

    Checks: host header injection, rate limiting.
    """
    if scope_engine and not scope_engine.is_in_scope(url):
        return VulnTestResult(
            test_type="reset",
            vulnerable=False,
            title=f"Password reset flaw on {url}",
            description=f"Skipped: {url} is out of scope",
        )
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []
    headers = dict(session.headers) if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE

    # Test 1: Host header injection
    attack_host = "evil.com"
    host_inject_headers = dict(headers)
    host_inject_headers["Host"] = attack_host
    host_inject_headers["X-Forwarded-Host"] = attack_host

    body = _json_mod.dumps({email_param: test_email})
    if "Content-Type" not in host_inject_headers:
        host_inject_headers["Content-Type"] = "application/json"

    resp_host = await http_client.request(
        method="POST",
        url=url,
        headers=host_inject_headers,
        cookies=cookies,
        body=body,
        source="test_reset",
        tags=["reset", "host_injection"],
    )
    request_ids.append(resp_host.request_id)
    collected_responses.append(resp_host)

    # Check if attack host appears in response (e.g., in a reset link)
    if attack_host in resp_host.body_text:
        vulnerable = True
        confidence = Confidence.CONFIRMED
        evidence.append(
            {
                "type": "host_header_injection",
                "injected_host": attack_host,
                "status_code": resp_host.status_code,
                "note": "Attack host reflected in password reset response",
            }
        )

    # Test 2: Rate limiting — send 5 rapid requests
    rate_successes = 0
    for i in range(5):
        resp_rate = await http_client.request(
            method="POST",
            url=url,
            headers=headers,
            cookies=cookies,
            body=body,
            source="test_reset",
            tags=["reset", "rate_limit"],
        )
        request_ids.append(resp_rate.request_id)
        collected_responses.append(resp_rate)
        if 200 <= resp_rate.status_code < 400:
            rate_successes += 1

    if rate_successes >= 5:
        evidence.append(
            {
                "type": "no_rate_limit",
                "successful_requests": rate_successes,
                "note": "All 5 rapid password reset requests succeeded — no rate limiting",
            }
        )

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="reset",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"Password reset flaw on {url}",
        description="Password reset flow vulnerability detected" if vulnerable else "",
        severity=Severity.HIGH if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=[
            "Ignore Host header when generating reset links",
            "Implement rate limiting on password reset endpoints",
        ]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    _persist_finding(context, hunt_id, result, url, "POST", email_param)
    _record_coverage(context, hunt_id, url, "POST", email_param, "reset")
    return result


async def test_ai(
    http_client: HttpClient,
    url: str,
    param: str,
    session: SessionState | None = None,
    payloads: list[str] | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
    max_test_seconds: float = 300,
) -> VulnTestResult:
    """Test LLM-powered features for prompt injection.

    Checks for system prompt exfiltration and instruction override.

    max_test_seconds caps total wall-clock time to prevent hangs on slow targets.
    """
    if scope_engine and not scope_engine.is_in_scope(url):
        return VulnTestResult(
            test_type="ai",
            vulnerable=False,
            title=f"Prompt injection on {url}",
            description=f"Skipped: {url} is out of scope",
        )
    payloads = payloads or ai_payloads.ALL
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []
    headers = session.headers if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE
    _deadline = asyncio.get_running_loop().time() + max_test_seconds

    for payload in payloads:
        if asyncio.get_running_loop().time() > _deadline:
            logger.warning("test_ai timed out after %.0fs on %s", max_test_seconds, url)
            break
        test_url = _inject_param(url, param, payload)

        resp = await http_client.request(
            method="GET",
            url=test_url,
            headers=headers,
            cookies=cookies,
            source="test_ai",
            tags=["ai", param],
        )
        request_ids.append(resp.request_id)
        collected_responses.append(resp)
        body_lower = resp.body_text.lower()

        # Check for canary markers (instruction override success)
        for marker in ai_payloads.CANARY_MARKERS:
            if marker.lower() in body_lower:
                vulnerable = True
                confidence = Confidence.CONFIRMED
                evidence.append(
                    {
                        "type": "instruction_override",
                        "payload": payload,
                        "marker": marker,
                        "request_id": resp.request_id,
                    }
                )
                break

        # Check for system prompt leak indicators (weighted scoring)
        if not vulnerable:
            strong = sum(2 for ind in ai_payloads.LEAK_INDICATORS_STRONG if ind in body_lower)
            weak = sum(1 for ind in ai_payloads.LEAK_INDICATORS_WEAK if ind in body_lower)
            leak_score = strong + weak
            if leak_score >= 4:
                vulnerable = True
                confidence = Confidence.LIKELY
                evidence.append(
                    {
                        "type": "system_prompt_leak",
                        "payload": payload,
                        "leak_score": leak_score,
                        "request_id": resp.request_id,
                    }
                )

        if vulnerable:
            break

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="ai",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"Prompt injection on {url}",
        description="LLM prompt injection detected" if vulnerable else "",
        severity=Severity.HIGH if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=[
            "Implement input sanitization for LLM inputs",
            "Use system prompt protection techniques",
            "Separate user input from system instructions",
        ]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    _persist_finding(context, hunt_id, result, url, "GET", param)
    _record_coverage(context, hunt_id, url, "GET", param, "ai")
    return result


async def test_ai_conversation(
    http_client: HttpClient,
    url: str,
    session: SessionState | None = None,
    conversations: list[list[str]] | None = None,
    tool_payloads: list[str] | None = None,
    indirect_payloads: list[str] | None = None,
    content_type: str = "application/json",
    message_field: str = "message",
    history_field: str = "messages",
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
    max_test_seconds: float = 300,
) -> VulnTestResult:
    """Test LLM features with multi-turn conversations, tool abuse, and indirect injection.

    Unlike test_ai (single GET requests), this sends POST requests with JSON bodies
    and accumulates conversation history across turns.
    """
    if scope_engine and not scope_engine.is_in_scope(url):
        return VulnTestResult(
            test_type="ai",
            vulnerable=False,
            title=f"Multi-turn prompt injection on {url}",
            description=f"Skipped: {url} is out of scope",
        )

    if conversations is None:
        conversations = ai_payloads.CONVERSATIONS
    if tool_payloads is None:
        tool_payloads = ai_payloads.TOOL_ABUSE
    if indirect_payloads is None:
        indirect_payloads = ai_payloads.INDIRECT

    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    collected_responses: list[HttpResponse] = []
    headers = dict(session.headers) if session else {}
    cookies = dict(session.cookies) if session else {}
    if "Content-Type" not in headers and "content-type" not in headers:
        headers["Content-Type"] = content_type
    vulnerable = False
    confidence = Confidence.POSSIBLE
    _deadline = asyncio.get_running_loop().time() + max_test_seconds

    def _check_response(body_text: str, payload: str, request_id: int) -> bool:
        nonlocal vulnerable, confidence
        body_lower = body_text.lower()

        for marker in ai_payloads.CANARY_MARKERS:
            if marker.lower() in body_lower:
                vulnerable = True
                confidence = Confidence.CONFIRMED
                evidence.append(
                    {
                        "type": "instruction_override",
                        "payload": payload,
                        "marker": marker,
                        "request_id": request_id,
                    }
                )
                return True

        strong = sum(2 for ind in ai_payloads.LEAK_INDICATORS_STRONG if ind in body_lower)
        weak = sum(1 for ind in ai_payloads.LEAK_INDICATORS_WEAK if ind in body_lower)
        leak_score = strong + weak
        if leak_score >= 4:
            vulnerable = True
            confidence = Confidence.LIKELY
            evidence.append(
                {
                    "type": "system_prompt_leak",
                    "payload": payload,
                    "leak_score": leak_score,
                    "request_id": request_id,
                }
            )
            return True

        for indicator in ai_payloads.TOOL_ABUSE_INDICATORS:
            if indicator in body_lower:
                vulnerable = True
                confidence = Confidence.LIKELY
                evidence.append(
                    {
                        "type": "function_call",
                        "payload": payload,
                        "indicator": indicator,
                        "request_id": request_id,
                    }
                )
                return True

        for pattern in _AI_CRED_PATTERNS:
            if pattern.search(body_text):
                vulnerable = True
                confidence = Confidence.CONFIRMED
                evidence.append(
                    {
                        "type": "credential_leak",
                        "payload": payload,
                        "request_id": request_id,
                    }
                )
                return True

        return False

    # Mode 1: Multi-turn conversations
    for conversation in conversations:
        if vulnerable:
            break
        if asyncio.get_running_loop().time() > _deadline:
            logger.warning("test_ai_conversation timed out on %s", url)
            break

        history: list[str] = []
        for turn in conversation:
            if asyncio.get_running_loop().time() > _deadline:
                break

            body = _json_mod.dumps({message_field: turn, history_field: history})
            resp = await http_client.request(
                method="POST",
                url=url,
                headers=headers,
                cookies=cookies,
                body=body,
                source="test_ai_conversation",
                tags=["ai", "conversation"],
            )
            request_ids.append(resp.request_id)
            collected_responses.append(resp)
            history.append(turn)

            if _check_response(resp.body_text, turn, resp.request_id):
                break

    # Mode 2: Tool abuse (single-turn POST)
    if not vulnerable:
        for payload in tool_payloads:
            if asyncio.get_running_loop().time() > _deadline:
                break

            body = _json_mod.dumps({message_field: payload})
            resp = await http_client.request(
                method="POST",
                url=url,
                headers=headers,
                cookies=cookies,
                body=body,
                source="test_ai_conversation",
                tags=["ai", "tool_abuse"],
            )
            request_ids.append(resp.request_id)
            collected_responses.append(resp)

            if _check_response(resp.body_text, payload, resp.request_id):
                break

    # Mode 3: Indirect injection (single-turn POST)
    if not vulnerable:
        for payload in indirect_payloads:
            if asyncio.get_running_loop().time() > _deadline:
                break

            body = _json_mod.dumps({message_field: payload})
            resp = await http_client.request(
                method="POST",
                url=url,
                headers=headers,
                cookies=cookies,
                body=body,
                source="test_ai_conversation",
                tags=["ai", "indirect"],
            )
            request_ids.append(resp.request_id)
            collected_responses.append(resp)

            if _check_response(resp.body_text, payload, resp.request_id):
                break

    waf_detected = not vulnerable and _detect_waf(collected_responses)
    result = VulnTestResult(
        test_type="ai",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"Multi-turn prompt injection on {url}",
        description="LLM prompt injection detected via conversation" if vulnerable else "",
        severity=Severity.HIGH if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=[
            "Implement input sanitization for LLM inputs",
            "Use system prompt protection techniques",
            "Separate user input from system instructions",
            "Restrict tool/function calling to whitelisted operations",
        ]
        if vulnerable
        else [],
        waf_detected=waf_detected,
    )
    _persist_finding(context, hunt_id, result, url, "POST", "")
    _record_coverage(context, hunt_id, url, "POST", "", "ai")
    return result


def _extract_json_keys(data: Any, prefix: str = "") -> set[str]:
    """Extract the set of key paths from a JSON structure for structural comparison."""
    keys: set[str] = set()
    if isinstance(data, dict):
        for k, v in data.items():
            path = f"{prefix}.{k}" if prefix else k
            keys.add(path)
            keys.update(_extract_json_keys(v, path))
    elif isinstance(data, list):
        keys.add(f"{prefix}[]")
        if data:
            keys.update(_extract_json_keys(data[0], f"{prefix}[]"))
    return keys


def _detect_waf(responses: list[HttpResponse]) -> bool:
    """Return True if responses suggest WAF blocking rather than clean results."""
    if len(responses) < 3:
        return False

    has_waf_signature = [
        any(sig in r.body_text.lower() for sig in _WAF_BODY_SIGNATURES) for r in responses
    ]

    if all(r.status_code in _WAF_STATUS_CODES for r in responses):
        bodies = [r.body_text.lower().strip() for r in responses]
        unique_bodies = set(bodies)
        if len(unique_bodies) <= 2 and any(has_waf_signature):
            return True

    if all(has_waf_signature):
        return True

    return False


def _bodies_similar(body_a: bytes, body_b: bytes, threshold: float = 0.7) -> bool:
    """Check if two response bodies are similar enough to indicate same content.

    Uses exact comparison, then JSON-aware structural comparison for JSON bodies
    (comparing key paths rather than values), then falls back to line-based
    overlap for non-JSON content.

    This prevents false positives from per-user JSON endpoints (/api/me) where
    the structure is identical but values differ, while still catching true
    similarity in non-JSON responses.
    """
    if body_a == body_b:
        return True
    if not body_a or not body_b:
        return not body_a and not body_b
    # Length-ratio heuristic — bodies must be similar length
    len_ratio = min(len(body_a), len(body_b)) / max(len(body_a), len(body_b))
    if len_ratio < threshold:
        return False

    # Try JSON-aware comparison: if both parse as JSON, compare structure AND values.
    # Key-only comparison would cause false positives (same schema, different user data).
    try:
        json_a = _json_mod.loads(body_a)
        json_b = _json_mod.loads(body_b)
        keys_a = _extract_json_keys(json_a)
        keys_b = _extract_json_keys(json_b)
        if keys_a and keys_b:
            key_overlap = len(keys_a & keys_b) / max(len(keys_a | keys_b), 1)
            if key_overlap < threshold:
                return False
            # Same structure — compare serialized values for each shared key
            # to avoid false positives from APIs with identical schemas but
            # different per-user data.
            flat_a = _json_mod.dumps(json_a, sort_keys=True, default=str)
            flat_b = _json_mod.dumps(json_b, sort_keys=True, default=str)
            if flat_a == flat_b:
                return True
            # Count matching vs differing value tokens
            tokens_a = flat_a.split(",")
            tokens_b = flat_b.split(",")
            token_set_a = set(tokens_a)
            token_set_b = set(tokens_b)
            token_overlap = len(token_set_a & token_set_b) / max(len(token_set_a | token_set_b), 1)
            return token_overlap > threshold
    except (ValueError, TypeError):
        pass

    # Non-JSON fallback: line-based overlap excluding JSON structural lines
    lines_a = {ln for ln in body_a.split(b"\n") if not _JSON_STRUCTURAL_RE.match(ln)}
    lines_b = {ln for ln in body_b.split(b"\n") if not _JSON_STRUCTURAL_RE.match(ln)}
    if not lines_a or not lines_b:
        return len_ratio > threshold
    overlap = len(lines_a & lines_b) / max(len(lines_a | lines_b), 1)
    return overlap > threshold
