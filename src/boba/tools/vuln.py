"""Vulnerability testing tools — compose interaction primitives into automated checks."""

from __future__ import annotations

from typing import Any
import re
from urllib.parse import quote, unquote, urlencode, urlparse, parse_qs, urlunparse

from boba.core.models import (
    Confidence,
    Severity,
    SessionState,
    VulnTestResult,
)
from boba.interaction.http import HttpClient
from boba.interaction.oob import OOBManager
from boba.payloads import sqli as sqli_payloads
from boba.payloads import ssrf as ssrf_payloads
from boba.payloads import xss as xss_payloads
from boba.payloads import auth as auth_payloads


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


async def test_idor(
    http_client: HttpClient,
    session_a: SessionState,
    session_b: SessionState,
    endpoint: str,
    method: str = "GET",
    body: str | None = None,
    object_ids: list[str] | None = None,
) -> VulnTestResult:
    """Test for Insecure Direct Object Reference (IDOR).

    1. Request endpoint as User A (owner) → response_a
    2. Request same endpoint as User B (attacker) → response_b
    3. Request with no auth → response_unauth
    4. Compare: if response_b ≈ response_a AND response_b ≠ response_unauth → IDOR
    """
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []

    # Request as User A (owner)
    resp_a = await http_client.request(
        method=method, url=endpoint,
        headers=session_a.headers, cookies=session_a.cookies,
        body=body, source="test_idor",
        session_name=session_a.name, tags=["idor", "user_a"],
    )
    request_ids.append(resp_a.request_id)

    # Request as User B (attacker)
    resp_b = await http_client.request(
        method=method, url=endpoint,
        headers=session_b.headers, cookies=session_b.cookies,
        body=body, source="test_idor",
        session_name=session_b.name, tags=["idor", "user_b"],
    )
    request_ids.append(resp_b.request_id)

    # Request with no auth
    resp_unauth = await http_client.request(
        method=method, url=endpoint,
        body=body, source="test_idor",
        tags=["idor", "no_auth"],
    )
    request_ids.append(resp_unauth.request_id)

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
            vulnerable = True
            confidence = Confidence.LIKELY
            description = (
                f"User B ({session_b.name}) received {resp_b.status_code} for {endpoint}, "
                f"same as User A ({resp_a.status_code}), "
                f"while unauthenticated got {resp_unauth.status_code}. "
                "Bodies differ — may be a shared endpoint returning user-specific data."
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

    evidence.append({
        "user_a_status": resp_a.status_code,
        "user_b_status": resp_b.status_code,
        "unauth_status": resp_unauth.status_code,
        "body_length_a": len(resp_a.body),
        "body_length_b": len(resp_b.body),
        "body_length_unauth": len(resp_unauth.body),
    })

    # Test additional object IDs if provided (run regardless of confidence
    # to gather enumeration evidence that can upgrade a POSSIBLE to CONFIRMED)
    if object_ids:
        for obj_id in object_ids:
            # Replace the last path segment with the new object ID
            parsed_ep = urlparse(endpoint)
            path_parts = parsed_ep.path.rstrip("/").split("/")
            path_parts[-1] = obj_id
            test_url = urlunparse(parsed_ep._replace(path="/".join(path_parts)))
            resp = await http_client.request(
                method=method, url=test_url,
                headers=session_b.headers, cookies=session_b.cookies,
                source="test_idor", session_name=session_b.name,
                tags=["idor", "enum"],
            )
            request_ids.append(resp.request_id)
            if 200 <= resp.status_code < 400:
                evidence.append({"enumerated_id": obj_id, "status": resp.status_code})
                if not vulnerable:
                    vulnerable = True
                    confidence = Confidence.LIKELY
                    description = (
                        f"User B ({session_b.name}) can enumerate object IDs on {endpoint}."
                    )

    return VulnTestResult(
        test_type="idor",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"IDOR on {endpoint}",
        description=description,
        severity=Severity.HIGH if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=["Implement proper authorization checks per-resource"] if vulnerable else [],
    )


async def test_ssrf(
    http_client: HttpClient,
    url: str,
    method: str = "GET",
    injection_points: list[dict] | None = None,
    payloads: list[str] | None = None,
    session: SessionState | None = None,
    oob_manager: OOBManager | None = None,
    poll_timeout_seconds: int = 10,
) -> VulnTestResult:
    """Test for Server-Side Request Forgery (SSRF).

    Injects internal URLs and OOB callbacks into parameters.
    """
    payloads = payloads or ssrf_payloads.ALL
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    headers = session.headers if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE

    # Default injection: replace param values in URL
    if not injection_points:
        injection_points = [{"location": "url_param", "name": "url"}]

    for point in injection_points:
        param_name = point.get("name", "url")

        for payload in payloads:
            # Build the request with injected payload (properly URL-encoded)
            test_url = _inject_param(url, param_name, payload)

            resp = await http_client.request(
                method=method, url=test_url,
                headers=headers, cookies=cookies,
                source="test_ssrf",
                tags=["ssrf", param_name],
            )
            request_ids.append(resp.request_id)

            # Check for strong SSRF indicators in response (content that could
            # only appear if the server fetched an internal resource).
            # Use context-aware regex to reduce false positives from
            # product names or error messages containing indicator substrings.
            ssrf_indicator_patterns = [
                (r"root:[^:]*:\d+:\d+:", "passwd_entry"),       # /etc/passwd format
                (r"/bin/(ba)?sh", "shell_path"),                 # Shell binary path
                (r"ami-[0-9a-f]{5,}", "aws_ami_id"),            # AWS AMI ID format
                (r"instance-id\b", "aws_instance"),              # AWS metadata field
                (r"computeMetadata/", "gcp_metadata"),           # GCP metadata path
            ]
            for pattern, indicator_type in ssrf_indicator_patterns:
                if re.search(pattern, resp.body_text, re.IGNORECASE):
                    vulnerable = True
                    confidence = Confidence.CONFIRMED
                    evidence.append({
                        "payload": payload,
                        "param": param_name,
                        "indicator": indicator_type,
                        "status_code": resp.status_code,
                        "request_id": resp.request_id,
                    })
                    break

            # Cloud metadata 200 check — always collect evidence even if
            # already flagged, since metadata access is higher severity
            if resp.status_code == 200 and "169.254.169.254" in payload:
                if not vulnerable:
                    vulnerable = True
                    confidence = Confidence.LIKELY
                evidence.append({
                    "payload": payload,
                    "param": param_name,
                    "note": "200 response for cloud metadata URL",
                    "request_id": resp.request_id,
                })

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
                method=method, url=test_url,
                headers=headers, cookies=cookies,
                source="test_ssrf", tags=["ssrf", "blind"],
            )
            request_ids.append(resp.request_id)

        # Poll for callbacks
        interactions = await oob_manager.poll(
            timeout_seconds=poll_timeout_seconds
        )
        if interactions:
            vulnerable = True
            confidence = Confidence.CONFIRMED
            for i in interactions:
                evidence.append({
                    "type": "oob_callback",
                    "interaction": i,
                })

    return VulnTestResult(
        test_type="ssrf",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"SSRF on {url}",
        description="Server-side request forgery detected" if vulnerable else "",
        severity=Severity.CRITICAL if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=["Validate and whitelist URLs server-side", "Block internal IPs"] if vulnerable else [],
    )


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
) -> VulnTestResult:
    """Test for Cross-Site Scripting (XSS).

    1. Reflected: inject payloads, check if they appear unescaped in response
    2. DOM-based: render in browser, check if canary JS executes
    3. Blind: inject OOB callback payloads
    """
    payloads = payloads or xss_payloads.BASIC
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    headers = session.headers if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE

    test_params = params or {"q": ""}

    for param_name in test_params:
        for payload in payloads:
            # Build URL with injected payload (properly URL-encoded)
            test_url = _inject_param(url, param_name, payload)

            resp = await http_client.request(
                method=method, url=test_url,
                headers=headers, cookies=cookies,
                source="test_xss", tags=["xss", param_name],
            )
            request_ids.append(resp.request_id)

            # Check reflection — payload appears unescaped in response.
            # Also check the URL-decoded form for encoding bypass payloads
            # (servers typically decode parameters before reflecting).
            decoded_payload = unquote(payload)
            if payload in resp.body_text:
                vulnerable = True
                confidence = Confidence.CONFIRMED
                evidence.append({
                    "type": "reflected",
                    "payload": payload,
                    "param": param_name,
                    "request_id": resp.request_id,
                })
                break  # Found confirmed XSS for this param

            if decoded_payload != payload and decoded_payload in resp.body_text:
                vulnerable = True
                confidence = Confidence.CONFIRMED
                evidence.append({
                    "type": "reflected_decoded",
                    "payload": payload,
                    "decoded": decoded_payload,
                    "param": param_name,
                    "request_id": resp.request_id,
                })
                break

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
                evidence.append({
                    "type": "partial_reflection",
                    "payload": payload,
                    "param": param_name,
                    "note": f"Inner content '{inner}' reflected without tags",
                    "request_id": resp.request_id,
                })

        if vulnerable:
            break

    # DOM-based XSS check via browser
    if check_dom and browser and not vulnerable:
        for param_name in test_params:
            for canary in xss_payloads.DOM_CANARY:
                test_url = _inject_param(url, param_name, canary)
                await browser.navigate(test_url)
                fired = await browser.execute_js("() => window.__xss_fired === true")
                if fired:
                    vulnerable = True
                    confidence = Confidence.CONFIRMED
                    evidence.append({
                        "type": "dom_based",
                        "payload": canary,
                        "param": param_name,
                        "url": test_url,
                    })
                    break
            if vulnerable:
                break

    return VulnTestResult(
        test_type="xss",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"XSS on {url}",
        description="Cross-site scripting via parameter injection" if vulnerable else "",
        severity=Severity.MEDIUM if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=["Encode output contextually", "Implement Content-Security-Policy"] if vulnerable else [],
    )


async def test_sqli(
    http_client: HttpClient,
    url: str,
    method: str = "GET",
    params: dict[str, str] | None = None,
    session: SessionState | None = None,
    payloads: list[str] | None = None,
) -> VulnTestResult:
    """Test for SQL injection.

    1. Baseline: normal request
    2. Error-based: inject ' " ) → check for SQL error strings
    3. Boolean-based: true vs false conditions → compare response lengths
    4. Time-based: SLEEP payloads → check response time delta (≥3s over baseline)
    """
    payloads = payloads or sqli_payloads.ERROR_BASED
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    headers = session.headers if session else {}
    cookies = session.cookies if session else {}
    vulnerable = False
    confidence = Confidence.POSSIBLE

    test_params = params or {"id": "1"}

    for param_name, default_val in test_params.items():
        # Baseline: request with the normal parameter value, so true/false comparisons
        # are against the same endpoint shape (not the bare URL without the param).
        baseline_url = _inject_param(url, param_name, default_val)
        resp_baseline = await http_client.request(
            method=method, url=baseline_url,
            headers=headers, cookies=cookies,
            source="test_sqli", tags=["sqli", "baseline"],
        )
        request_ids.append(resp_baseline.request_id)
        # Error-based detection
        for payload in payloads:
            test_url = _inject_param(url, param_name, f"{default_val}{payload}")

            resp = await http_client.request(
                method=method, url=test_url,
                headers=headers, cookies=cookies,
                source="test_sqli", tags=["sqli", "error_based"],
            )
            request_ids.append(resp.request_id)

            # Check for SQL error signatures in response
            body_lower = resp.body_text.lower()
            for sig in sqli_payloads.ERROR_SIGNATURES:
                if sig.lower() in body_lower:
                    vulnerable = True
                    confidence = Confidence.CONFIRMED
                    evidence.append({
                        "type": "error_based",
                        "payload": payload,
                        "param": param_name,
                        "error_signature": sig,
                        "request_id": resp.request_id,
                    })
                    break
            if vulnerable:
                break

        if vulnerable:
            break

        # Boolean-based detection
        true_payload = "' AND '1'='1"
        false_payload = "' AND '1'='2"

        resp_true = await http_client.request(
            method=method,
            url=_inject_param(url, param_name, f"{default_val}{true_payload}"),
            headers=headers, cookies=cookies,
            source="test_sqli", tags=["sqli", "boolean_true"],
        )
        resp_false = await http_client.request(
            method=method,
            url=_inject_param(url, param_name, f"{default_val}{false_payload}"),
            headers=headers, cookies=cookies,
            source="test_sqli", tags=["sqli", "boolean_false"],
        )
        request_ids.extend([resp_true.request_id, resp_false.request_id])

        # If true/false conditions produce different response lengths, likely SQLi.
        # Use both absolute and relative thresholds to catch small and large responses.
        len_diff = abs(len(resp_true.body) - len(resp_false.body))
        baseline_len = max(len(resp_baseline.body), 1)
        relative_diff = len_diff / baseline_len
        if (
            resp_true.status_code == resp_false.status_code
            and (len_diff >= 20 or relative_diff >= 0.05)
            and len_diff > 0
            and resp_true.status_code == resp_baseline.status_code
        ):
            vulnerable = True
            confidence = Confidence.LIKELY
            evidence.append({
                "type": "boolean_based",
                "param": param_name,
                "true_length": len(resp_true.body),
                "false_length": len(resp_false.body),
                "diff": len_diff,
            })

        # Time-based detection — only if not already confirmed via error/boolean.
        # Uses multiple baseline samples to reduce false positives from network jitter.
        if not vulnerable:
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
                    method=method, url=baseline_url,
                    headers=headers, cookies=cookies,
                    source="test_sqli", tags=["sqli", "baseline_timing"],
                )
                request_ids.append(resp_bl.request_id)
                baseline_samples.append(resp_bl.elapsed_ms)
            baseline_median = sorted(baseline_samples)[len(baseline_samples) // 2]

            for payload in time_payloads:
                test_url = _inject_param(url, param_name, f"{default_val}{payload}")
                resp_time = await http_client.request(
                    method=method, url=test_url,
                    headers=headers, cookies=cookies,
                    source="test_sqli", tags=["sqli", "time_based"],
                    timeout_seconds=15.0,
                )
                request_ids.append(resp_time.request_id)
                # A SLEEP(5) payload should add ≥3s over the median baseline
                delay_ms = resp_time.elapsed_ms - baseline_median
                if delay_ms >= 3000:
                    vulnerable = True
                    confidence = Confidence.LIKELY
                    evidence.append({
                        "type": "time_based",
                        "payload": payload,
                        "param": param_name,
                        "baseline_median_ms": baseline_median,
                        "response_ms": resp_time.elapsed_ms,
                        "delay_ms": delay_ms,
                        "request_id": resp_time.request_id,
                    })
                    break

    return VulnTestResult(
        test_type="sqli",
        vulnerable=vulnerable,
        confidence=confidence,
        title=f"SQL Injection on {url}",
        description="SQL injection detected via error or boolean-based analysis" if vulnerable else "",
        severity=Severity.HIGH if vulnerable else Severity.INFO,
        evidence=evidence,
        request_ids=request_ids,
        recommendations=["Use parameterized queries", "Implement input validation"] if vulnerable else [],
    )


async def test_auth(
    http_client: HttpClient,
    endpoint: str,
    session: SessionState | None = None,
    jwt_token: str | None = None,
) -> VulnTestResult:
    """Test authentication/authorization controls.

    1. No-auth: request without credentials → should be 401/403
    2. JWT none algorithm: re-sign with alg=none
    3. JWT claim manipulation: modify role/admin claims
    """
    request_ids: list[int] = []
    evidence: list[dict[str, Any]] = []
    vulnerable = False
    confidence = Confidence.POSSIBLE

    # Test 1: No auth → should be denied
    resp_noauth = await http_client.request(
        method="GET", url=endpoint,
        source="test_auth", tags=["auth", "no_auth"],
    )
    request_ids.append(resp_noauth.request_id)

    if 200 <= resp_noauth.status_code < 400:
        vulnerable = True
        confidence = Confidence.CONFIRMED
        evidence.append({
            "type": "no_auth_access",
            "status_code": resp_noauth.status_code,
            "note": "Endpoint accessible without any authentication",
        })

    # Test 2: JWT manipulation (if token provided)
    if jwt_token and not vulnerable:
        try:
            # None algorithm attack
            none_token = auth_payloads.jwt_none_algorithm(jwt_token)
            resp_none = await http_client.request(
                method="GET", url=endpoint,
                headers={"Authorization": f"Bearer {none_token}"},
                source="test_auth", tags=["auth", "jwt_none"],
            )
            request_ids.append(resp_none.request_id)

            if 200 <= resp_none.status_code < 400:
                vulnerable = True
                confidence = Confidence.CONFIRMED
                evidence.append({
                    "type": "jwt_none_algorithm",
                    "status_code": resp_none.status_code,
                    "note": "JWT with alg=none accepted",
                })

            # Claim escalation
            for claims in auth_payloads.ESCALATION_CLAIMS:
                modified_token = auth_payloads.jwt_modify_claims(jwt_token, claims)
                resp_esc = await http_client.request(
                    method="GET", url=endpoint,
                    headers={"Authorization": f"Bearer {modified_token}"},
                    source="test_auth", tags=["auth", "jwt_escalation"],
                )
                request_ids.append(resp_esc.request_id)

                if 200 <= resp_esc.status_code < 400:
                    vulnerable = True
                    confidence = Confidence.LIKELY
                    evidence.append({
                        "type": "jwt_claim_escalation",
                        "modified_claims": claims,
                        "status_code": resp_esc.status_code,
                    })
                    break

        except (ValueError, KeyError, IndexError):
            # Invalid JWT format — skip JWT tests
            pass

    # Test 3: With valid session but accessing admin-like endpoints
    if session and not vulnerable:
        resp_auth = await http_client.request(
            method="GET", url=endpoint,
            headers=session.headers, cookies=session.cookies,
            source="test_auth", session_name=session.name,
            tags=["auth", "session"],
        )
        request_ids.append(resp_auth.request_id)

        # If regular user can access, check if it looks like an admin endpoint
        # Use regex with path-boundary matching to avoid false positives
        # like /gadmin or /read-admin-guide
        _ADMIN_RE = re.compile(r"/(admin|manage|internal|superuser)([/?#]|$)", re.IGNORECASE)
        if 200 <= resp_auth.status_code < 400:
            if _ADMIN_RE.search(endpoint):
                vulnerable = True
                confidence = Confidence.LIKELY
                evidence.append({
                    "type": "privilege_escalation",
                    "endpoint": endpoint,
                    "status_code": resp_auth.status_code,
                    "note": f"User '{session.name}' can access admin-like endpoint",
                })

    return VulnTestResult(
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
        ] if vulnerable else [],
    )


def _bodies_similar(body_a: bytes, body_b: bytes, threshold: float = 0.8) -> bool:
    """Check if two response bodies are similar enough to indicate same content.

    Uses both exact content hash comparison and length-ratio heuristic.
    This prevents false positives from two different resources that happen
    to be the same length.
    """
    if body_a == body_b:
        return True
    if not body_a or not body_b:
        return False
    # Length-ratio heuristic — bodies must be similar length AND share structural overlap
    len_ratio = min(len(body_a), len(body_b)) / max(len(body_a), len(body_b))
    if len_ratio < threshold:
        return False
    # Check for structural overlap: shared lines as a fraction of total unique lines
    lines_a = set(body_a.split(b"\n"))
    lines_b = set(body_b.split(b"\n"))
    if not lines_a or not lines_b:
        return len_ratio > threshold
    overlap = len(lines_a & lines_b) / max(len(lines_a | lines_b), 1)
    return overlap > threshold
