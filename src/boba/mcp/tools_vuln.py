"""MCP tools for vulnerability testing — 12 test tools."""

from __future__ import annotations

from typing import Annotated, Any

from boba.mcp.serializers import serialize_result
from boba.mcp.server import mcp, resources
from boba.tools import vuln


def _get_session(hunt_id: str, session_name: str | None):
    """Resolve a session name to a SessionState, or None."""
    if session_name is None:
        return None
    sm = resources.get_session_manager(hunt_id)
    return sm.get(session_name)


def _get_required_session(hunt_id: str, session_name: str):
    """Resolve a session name, raising if not found."""
    sm = resources.get_session_manager(hunt_id)
    session = sm.get(session_name)
    if session is None:
        raise ValueError(f"Session '{session_name}' not found for hunt {hunt_id}")
    return session


def _common_kwargs(hunt_id: str) -> dict[str, Any]:
    """Build the scope_engine / context / hunt_id kwargs shared by all vuln tools."""
    hunt = resources.get_hunt(hunt_id)
    return {
        "scope_engine": resources.get_scope_engine(hunt),
        "context": resources.get_context(),
        "hunt_id": hunt_id,
    }


@mcp.tool(description="Test an endpoint for IDOR (Insecure Direct Object Reference)")
async def test_idor(
    hunt_id: Annotated[str, "Hunt ID"],
    endpoint: Annotated[str, "URL to test (e.g. /api/user/123)"],
    session_a: Annotated[str, "Session name for User A"],
    session_b: Annotated[str, "Session name for User B"],
    method: Annotated[str, "HTTP method"] = "GET",
    body: Annotated[str | None, "Request body"] = None,
    object_ids: Annotated[list[str] | None, "Object IDs to enumerate"] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await vuln.test_idor(
        http_client=client,
        session_a=_get_required_session(hunt_id, session_a),
        session_b=_get_required_session(hunt_id, session_b),
        endpoint=endpoint,
        method=method,
        body=body,
        object_ids=object_ids,
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test for Server-Side Request Forgery (SSRF)")
async def test_ssrf(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL to test"],
    param: Annotated[str | None, "Parameter name to inject into"] = None,
    method: Annotated[str, "HTTP method"] = "GET",
    session_name: Annotated[str | None, "Session for authenticated testing"] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    injection_points = [{"location": "url_param", "name": param}] if param is not None else None
    oob = resources.get_oob_manager(hunt_id)
    try:
        await oob.start()
    except RuntimeError:
        pass  # already started
    result = await vuln.test_ssrf(
        http_client=client,
        url=url,
        method=method,
        injection_points=injection_points,
        session=_get_session(hunt_id, session_name),
        oob_manager=oob,
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test for SQL injection (error-based, boolean, time-based)")
async def test_sqli(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL to test"],
    param: Annotated[str, "Parameter name to inject into"],
    method: Annotated[str, "HTTP method"] = "GET",
    session_name: Annotated[str | None, "Session for authenticated testing"] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await vuln.test_sqli(
        http_client=client,
        url=url,
        method=method,
        params={param: "1"},
        session=_get_session(hunt_id, session_name),
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test for Cross-Site Scripting (XSS) — reflected, DOM, and blind")
async def test_xss(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL to test"],
    param: Annotated[str, "Parameter name to inject into"],
    method: Annotated[str, "HTTP method"] = "GET",
    check_dom: Annotated[bool, "Enable DOM-based XSS testing via browser"] = False,
    session_name: Annotated[str | None, "Session for authenticated testing"] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    browser = None
    if check_dom:
        browser = await resources.get_browser()
    result = await vuln.test_xss(
        http_client=client,
        url=url,
        method=method,
        params={param: "test"},
        session=_get_session(hunt_id, session_name),
        check_dom=check_dom,
        browser=browser,
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test for authentication and authorization bypass")
async def test_auth(
    hunt_id: Annotated[str, "Hunt ID"],
    endpoint: Annotated[str, "Protected endpoint to test"],
    method: Annotated[str, "HTTP method"] = "GET",
    session_name: Annotated[str | None, "Session to test with"] = None,
    jwt: Annotated[str | None, "JWT token for manipulation tests"] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await vuln.test_auth(
        http_client=client,
        endpoint=endpoint,
        session=_get_session(hunt_id, session_name),
        jwt_token=jwt,
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test for race conditions via concurrent requests")
async def test_race(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL to test"],
    session_name: Annotated[str, "Session for authenticated requests"],
    method: Annotated[str, "HTTP method"] = "POST",
    body: Annotated[str | None, "Request body"] = None,
    concurrency: Annotated[int, "Number of concurrent requests"] = 10,
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await vuln.test_race(
        http_client=client,
        session=_get_required_session(hunt_id, session_name),
        url=url,
        method=method,
        body=body,
        concurrency=concurrency,
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test for open redirect vulnerabilities")
async def test_redirect(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL to test"],
    param: Annotated[str, "Parameter name that controls redirect destination"],
    session_name: Annotated[str | None, "Session for authenticated testing"] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await vuln.test_redirect(
        http_client=client,
        url=url,
        param=param,
        session=_get_session(hunt_id, session_name),
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test for Cross-Site Request Forgery (CSRF) vulnerabilities")
async def test_csrf(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL to test"],
    session_name: Annotated[str, "Session for authenticated requests"],
    method: Annotated[str, "HTTP method"] = "POST",
    body: Annotated[str | None, "Request body"] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await vuln.test_csrf(
        http_client=client,
        session=_get_required_session(hunt_id, session_name),
        url=url,
        method=method,
        body=body,
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test for mass assignment / parameter pollution")
async def test_mass_assign(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL to test"],
    session_name: Annotated[str, "Session for authenticated requests"],
    method: Annotated[str, "HTTP method"] = "PUT",
    base_body: Annotated[dict | None, "Legitimate request body fields"] = None,
    extra_fields: Annotated[
        dict | None, "Forbidden fields to inject (e.g. {'isAdmin': true})"
    ] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await vuln.test_mass_assign(
        http_client=client,
        session=_get_required_session(hunt_id, session_name),
        url=url,
        method=method,
        base_body=base_body,
        extra_fields=extra_fields,
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test password reset flow for vulnerabilities")
async def test_reset(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "Password reset URL"],
    email_param: Annotated[str, "Parameter name for email field"] = "email",
    test_email: Annotated[str, "Email address for testing"] = "test@example.com",
    session_name: Annotated[str | None, "Session for authenticated testing"] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await vuln.test_reset(
        http_client=client,
        url=url,
        email_param=email_param,
        test_email=test_email,
        session=_get_session(hunt_id, session_name),
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test AI/LLM features for prompt injection (single-request)")
async def test_ai(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL of the AI/LLM endpoint"],
    param: Annotated[str, "Parameter name for user input"],
    method: Annotated[str, "HTTP method"] = "GET",
    session_name: Annotated[str | None, "Session for authenticated testing"] = None,
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await vuln.test_ai(
        http_client=client,
        url=url,
        param=param,
        session=_get_session(hunt_id, session_name),
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)


@mcp.tool(description="Test AI/LLM chatbots via multi-turn conversation (POST/JSON endpoints)")
async def test_ai_conversation(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "Chatbot API endpoint"],
    session_name: Annotated[str | None, "Session for authenticated testing"] = None,
    message_field: Annotated[str, "JSON field name for the user message"] = "message",
    history_field: Annotated[str, "JSON field name for conversation history"] = "messages",
) -> str:
    client = resources.get_http_client(hunt_id)
    result = await vuln.test_ai_conversation(
        http_client=client,
        url=url,
        session=_get_session(hunt_id, session_name),
        message_field=message_field,
        history_field=history_field,
        **_common_kwargs(hunt_id),
    )
    return serialize_result(result)
