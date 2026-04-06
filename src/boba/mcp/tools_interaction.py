"""MCP tools for interaction — sessions, HTTP client, browser, OOB listeners."""

from __future__ import annotations

from typing import Annotated, Any

from boba.mcp.serializers import serialize_result
from boba.mcp.server import mcp, resources


# =============================================================================
# Session management (7 tools)
# =============================================================================


@mcp.tool(description="Create a new authentication session for a hunt")
async def session_create(
    hunt_id: Annotated[str, "Hunt ID"],
    name: Annotated[str, "Unique session name (e.g. 'user_a', 'admin')"],
    target_url: Annotated[str, "Base URL this session targets"],
    auth_method: Annotated[str, "Auth method: form, cookie, bearer, basic, header"] = "form",
) -> str:
    from boba.core.models import AuthMethod

    sm = resources.get_session_manager(hunt_id)
    session = sm.create(name=name, target_url=target_url, auth_method=AuthMethod(auth_method))
    return serialize_result(_session_to_dict(session))


@mcp.tool(description="Authenticate a session with a Bearer token")
async def session_login_token(
    hunt_id: Annotated[str, "Hunt ID"],
    session_name: Annotated[str, "Session name"],
    token: Annotated[str, "Bearer token value"],
) -> str:
    sm = resources.get_session_manager(hunt_id)
    session = sm.login_bearer(session_name, token)
    return serialize_result(_session_to_dict(session))


@mcp.tool(description="Authenticate a session with HTTP Basic credentials")
async def session_login_basic(
    hunt_id: Annotated[str, "Hunt ID"],
    session_name: Annotated[str, "Session name"],
    username: Annotated[str, "Username"],
    password: Annotated[str, "Password"],
) -> str:
    sm = resources.get_session_manager(hunt_id)
    session = sm.login_basic(session_name, username, password)
    return serialize_result(_session_to_dict(session))


@mcp.tool(description="Authenticate a session with raw cookies")
async def session_login_cookies(
    hunt_id: Annotated[str, "Hunt ID"],
    session_name: Annotated[str, "Session name"],
    cookies: Annotated[dict[str, str], "Cookie name-value pairs"],
) -> str:
    sm = resources.get_session_manager(hunt_id)
    session = sm.login_cookies(session_name, cookies)
    return serialize_result(_session_to_dict(session))


@mcp.tool(description="Authenticate a session with a custom header")
async def session_login_header(
    hunt_id: Annotated[str, "Hunt ID"],
    session_name: Annotated[str, "Session name"],
    header_name: Annotated[str, "Header name (e.g. 'X-API-Key')"],
    header_value: Annotated[str, "Header value"],
) -> str:
    sm = resources.get_session_manager(hunt_id)
    session = sm.login_header(session_name, header_name, header_value)
    return serialize_result(_session_to_dict(session))


@mcp.tool(description="List all sessions for a hunt")
async def session_list(
    hunt_id: Annotated[str, "Hunt ID"],
) -> str:
    sm = resources.get_session_manager(hunt_id)
    sessions = sm.list_sessions()
    return serialize_result([_session_to_dict(s) for s in sessions])


@mcp.tool(description="Delete a session")
async def session_delete(
    hunt_id: Annotated[str, "Hunt ID"],
    session_name: Annotated[str, "Session name to delete"],
) -> str:
    sm = resources.get_session_manager(hunt_id)
    sm.delete(session_name)
    return serialize_result({"deleted": session_name})


def _session_to_dict(session: Any) -> dict[str, Any]:
    """Convert a SessionState to a JSON-safe dict."""
    return {
        "name": session.name,
        "target_url": session.target_url,
        "auth_method": session.auth_method.value
        if hasattr(session.auth_method, "value")
        else str(session.auth_method),
        "cookies": session.cookies,
        "headers": session.headers,
        "tokens": session.tokens,
        "is_valid": session.is_valid,
    }


# =============================================================================
# HTTP client (4 tools)
# =============================================================================


@mcp.tool(description="Send an HTTP request and record it in history")
async def http_request(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "Target URL"],
    method: Annotated[str, "HTTP method (GET, POST, PUT, DELETE, etc.)"] = "GET",
    headers: Annotated[dict[str, str] | None, "Request headers"] = None,
    body: Annotated[str | None, "Request body"] = None,
    cookies: Annotated[dict[str, str] | None, "Cookies to send"] = None,
    session_name: Annotated[str | None, "Session name for auth headers/cookies"] = None,
    follow_redirects: Annotated[bool, "Follow HTTP redirects"] = True,
) -> str:
    client = resources.get_http_client(hunt_id)
    h, c = _resolve_session(hunt_id, session_name, headers, cookies)
    resp = await client.request(
        method=method,
        url=url,
        headers=h,
        body=body,
        cookies=c,
        follow_redirects=follow_redirects,
        session_name=session_name,
    )
    return serialize_result(_response_to_dict(resp))


@mcp.tool(description="Replay a previous request from HTTP history with optional modifications")
async def http_replay(
    hunt_id: Annotated[str, "Hunt ID"],
    request_id: Annotated[int, "HTTP history request ID to replay"],
    modify_headers: Annotated[dict[str, str] | None, "Headers to override"] = None,
    modify_body: Annotated[str | None, "Body to override"] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    modifications: dict[str, Any] = {}
    if modify_headers is not None:
        modifications["headers"] = modify_headers
    if modify_body is not None:
        modifications["body"] = modify_body
    resp = await client.replay(request_id, modifications=modifications or None)
    return serialize_result(_response_to_dict(resp))


@mcp.tool(description="Compare two HTTP responses from history")
async def http_compare(
    hunt_id: Annotated[str, "Hunt ID"],
    request_id_a: Annotated[int, "First request ID"],
    request_id_b: Annotated[int, "Second request ID"],
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await client.compare(request_id_a, request_id_b)
    return serialize_result(result)


@mcp.tool(description="Fuzz parameters with payloads (Burp Intruder equivalent)")
async def http_fuzz(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL with § markers for injection points"],
    method: Annotated[str, "HTTP method"] = "GET",
    headers: Annotated[dict[str, str] | None, "Headers (may contain § markers)"] = None,
    body: Annotated[str | None, "Body (may contain § markers)"] = None,
    payloads: Annotated[dict[str, list[str]] | None, "Position name → payload list"] = None,
    attack_type: Annotated[str, "sniper, battering_ram, pitchfork, or cluster_bomb"] = "sniper",
    rate_limit: Annotated[int, "Max requests per second"] = 10,
    session_name: Annotated[str | None, "Session for auth"] = None,
) -> str:
    from boba.core.models import FuzzAttackType

    client = resources.get_http_client(hunt_id)
    h, c = _resolve_session(hunt_id, session_name, headers, None)
    result = await client.fuzz(
        method=method,
        url=url,
        headers=h,
        body=body,
        payloads=payloads,
        attack_type=FuzzAttackType(attack_type),
        rate_limit=rate_limit,
        cookies=c,
        session_name=session_name,
    )
    return serialize_result(result)


def _resolve_session(
    hunt_id: str,
    session_name: str | None,
    headers: dict[str, str] | None,
    cookies: dict[str, str] | None,
) -> tuple[dict[str, str] | None, dict[str, str] | None]:
    """Merge session auth into headers/cookies if a session is specified."""
    if session_name is None:
        return headers, cookies
    sm = resources.get_session_manager(hunt_id)
    session_headers = sm.apply_to_headers(session_name)
    session_cookies = sm.apply_to_cookies(session_name)
    merged_headers = {**session_headers, **(headers or {})}
    merged_cookies = {**session_cookies, **(cookies or {})}
    return merged_headers if merged_headers else None, merged_cookies if merged_cookies else None


def _response_to_dict(resp: Any) -> dict[str, Any]:
    """Convert an HttpResponse to a JSON-safe dict."""
    return {
        "request_id": resp.request_id,
        "status_code": resp.status_code,
        "headers": resp.headers,
        "body_text": resp.body_text[:5000] if resp.body_text else "",
        "body_length": len(resp.body) if resp.body else 0,
        "elapsed_ms": resp.elapsed_ms,
        "redirect_chain": resp.redirect_chain,
    }


# =============================================================================
# Browser (3 tools)
# =============================================================================


@mcp.tool(description="Navigate to a URL in the headless browser")
async def browser_navigate(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL to navigate to"],
    session_name: Annotated[str | None, "Session to apply (cookies/headers)"] = None,
    wait_until: Annotated[
        str, "Wait condition: networkidle, load, domcontentloaded"
    ] = "networkidle",
) -> str:
    resources.get_hunt(hunt_id)  # validate
    browser = await resources.get_browser()
    if session_name:
        sm = resources.get_session_manager(hunt_id)
        session = sm.get(session_name)
        if session is None:
            raise ValueError(f"Session '{session_name}' not found for hunt {hunt_id}")
        await browser.apply_session(session)
    page_info = await browser.navigate(url=url, wait_until=wait_until)
    return serialize_result(page_info)


@mcp.tool(description="Take a screenshot of the current browser page")
async def browser_screenshot(
    hunt_id: Annotated[str, "Hunt ID"],
    output_path: Annotated[str, "File path to save the screenshot"],
    full_page: Annotated[bool, "Capture full scrollable page"] = True,
) -> str:
    resources.get_hunt(hunt_id)  # validate
    browser = await resources.get_browser()
    saved_path = await browser.screenshot(path=output_path, full_page=full_page)
    return serialize_result({"path": str(saved_path)})


@mcp.tool(
    description="Extract structured DOM data (forms, links, scripts, inputs) from current page"
)
async def browser_extract(
    hunt_id: Annotated[str, "Hunt ID"],
) -> str:
    resources.get_hunt(hunt_id)  # validate
    browser = await resources.get_browser()
    extraction = await browser.extract()
    return serialize_result(extraction)


# =============================================================================
# OOB listeners (3 tools)
# =============================================================================


@mcp.tool(description="Create an out-of-band callback listener for blind vulnerability testing")
async def oob_create_listener(
    hunt_id: Annotated[str, "Hunt ID"],
    purpose: Annotated[str, "What this listener tests (e.g. 'blind SSRF on url param')"],
    target_url: Annotated[str | None, "URL being tested"] = None,
    parameter: Annotated[str | None, "Parameter being injected"] = None,
) -> str:
    oob = resources.get_oob_manager(hunt_id)
    try:
        await oob.start()
    except RuntimeError:
        pass  # already started
    callback_domain = await oob.create_listener(
        purpose=purpose, target_url=target_url, parameter=parameter
    )
    return serialize_result({"callback_domain": callback_domain, "purpose": purpose})


@mcp.tool(description="Get a payload URL from an OOB callback domain")
async def oob_get_payload(
    hunt_id: Annotated[str, "Hunt ID"],
    callback_domain: Annotated[str, "Callback domain from oob_create_listener"],
    protocol: Annotated[str, "Protocol: http or https"] = "http",
) -> str:
    oob = resources.get_oob_manager(hunt_id)
    url = oob.get_payload_url(callback_domain, protocol=protocol)
    return serialize_result({"payload_url": url})


@mcp.tool(description="Poll for out-of-band interactions (DNS, HTTP callbacks)")
async def oob_poll(
    hunt_id: Annotated[str, "Hunt ID"],
    listener_id: Annotated[str | None, "Specific listener ID to poll (omit for all)"] = None,
    timeout_seconds: Annotated[int, "How long to poll"] = 30,
) -> str:
    oob = resources.get_oob_manager(hunt_id)
    interactions = await oob.poll(listener_id=listener_id, timeout_seconds=timeout_seconds)
    return serialize_result(interactions)
