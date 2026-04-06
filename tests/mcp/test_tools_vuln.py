"""Tests for MCP vulnerability testing tools — mock vuln functions."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from boba.core.models import Confidence, Severity, VulnTestResult

pytestmark = pytest.mark.usefixtures("_patch_resources")


def _text(content_blocks) -> dict:
    return json.loads(content_blocks[0].text)


async def _create_hunt(mcp_server, name="Vuln Test"):
    content, _ = await mcp_server.call_tool("hunt_create", {"name": name})
    return json.loads(content[0].text)["hunt_id"]


async def _create_session(mcp_server, hunt_id, name="user"):
    await mcp_server.call_tool(
        "session_create",
        {"hunt_id": hunt_id, "name": name, "target_url": "https://example.com"},
    )
    await mcp_server.call_tool(
        "session_login_token",
        {"hunt_id": hunt_id, "session_name": name, "token": f"tok_{name}"},
    )


def _vuln_result(test_type: str, vulnerable: bool = True, **kwargs) -> VulnTestResult:
    return VulnTestResult(
        test_type=test_type,
        vulnerable=vulnerable,
        confidence=kwargs.get("confidence", Confidence.CONFIRMED),
        title=kwargs.get("title", f"{test_type} vulnerability found"),
        description=kwargs.get("description", "Test description"),
        severity=kwargs.get("severity", Severity.HIGH),
        evidence=kwargs.get("evidence", [{"detail": "proof"}]),
        request_ids=kwargs.get("request_ids", [1, 2]),
    )


def _inject_mock_client(mcp_resources, hunt_id):
    """Inject a mock HttpClient so vuln tools don't need a real one."""
    mock = MagicMock()
    mock.request = AsyncMock()
    mock.close = AsyncMock()
    mcp_resources._http_clients[hunt_id] = mock
    return mock


# -- test_idor ----------------------------------------------------------------


async def test_idor(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    await _create_session(mcp_server, hunt_id, "user_a")
    await _create_session(mcp_server, hunt_id, "user_b")
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("idor"))
    with patch("boba.mcp.tools_vuln.vuln.test_idor", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_idor",
            {
                "hunt_id": hunt_id,
                "endpoint": "https://example.com/api/user/123",
                "session_a": "user_a",
                "session_b": "user_b",
            },
        )

    data = _text(content)
    assert data["test_type"] == "idor"
    assert data["vulnerable"] is True
    assert data["confidence"] == "confirmed"
    mock_fn.assert_called_once()


# -- test_ssrf ----------------------------------------------------------------


async def test_ssrf(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _inject_mock_client(mcp_resources, hunt_id)
    # Mock OOB manager
    mock_oob = MagicMock()
    mock_oob.start = AsyncMock()
    mcp_resources._oob_managers[hunt_id] = mock_oob

    mock_fn = AsyncMock(return_value=_vuln_result("ssrf"))
    with patch("boba.mcp.tools_vuln.vuln.test_ssrf", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_ssrf",
            {"hunt_id": hunt_id, "url": "https://example.com/fetch", "param": "url"},
        )

    data = _text(content)
    assert data["test_type"] == "ssrf"
    assert data["vulnerable"] is True


# -- test_sqli ----------------------------------------------------------------


async def test_sqli(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("sqli"))
    with patch("boba.mcp.tools_vuln.vuln.test_sqli", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_sqli",
            {"hunt_id": hunt_id, "url": "https://example.com/search", "param": "q"},
        )

    data = _text(content)
    assert data["test_type"] == "sqli"


# -- test_xss -----------------------------------------------------------------


async def test_xss(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("xss"))
    with patch("boba.mcp.tools_vuln.vuln.test_xss", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_xss",
            {"hunt_id": hunt_id, "url": "https://example.com/search", "param": "q"},
        )

    data = _text(content)
    assert data["test_type"] == "xss"


# -- test_auth -----------------------------------------------------------------


async def test_auth(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("auth"))
    with patch("boba.mcp.tools_vuln.vuln.test_auth", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_auth",
            {"hunt_id": hunt_id, "endpoint": "https://example.com/admin"},
        )

    data = _text(content)
    assert data["test_type"] == "auth"


# -- test_race -----------------------------------------------------------------


async def test_race(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    await _create_session(mcp_server, hunt_id, "racer")
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("race"))
    with patch("boba.mcp.tools_vuln.vuln.test_race", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_race",
            {
                "hunt_id": hunt_id,
                "url": "https://example.com/api/claim",
                "session_name": "racer",
            },
        )

    data = _text(content)
    assert data["test_type"] == "race"


# -- test_redirect -------------------------------------------------------------


async def test_redirect(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("redirect"))
    with patch("boba.mcp.tools_vuln.vuln.test_redirect", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_redirect",
            {"hunt_id": hunt_id, "url": "https://example.com/redirect", "param": "next"},
        )

    data = _text(content)
    assert data["test_type"] == "redirect"


# -- test_csrf -----------------------------------------------------------------


async def test_csrf(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    await _create_session(mcp_server, hunt_id, "csrf_user")
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("csrf"))
    with patch("boba.mcp.tools_vuln.vuln.test_csrf", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_csrf",
            {
                "hunt_id": hunt_id,
                "url": "https://example.com/settings",
                "session_name": "csrf_user",
            },
        )

    data = _text(content)
    assert data["test_type"] == "csrf"


# -- test_mass_assign ----------------------------------------------------------


async def test_mass_assign(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    await _create_session(mcp_server, hunt_id, "mass_user")
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("mass_assignment"))
    with patch("boba.mcp.tools_vuln.vuln.test_mass_assign", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_mass_assign",
            {
                "hunt_id": hunt_id,
                "url": "https://example.com/api/profile",
                "session_name": "mass_user",
                "extra_fields": {"isAdmin": True},
            },
        )

    data = _text(content)
    assert data["test_type"] == "mass_assignment"


# -- test_reset ----------------------------------------------------------------


async def test_reset(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("password_reset"))
    with patch("boba.mcp.tools_vuln.vuln.test_reset", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_reset",
            {"hunt_id": hunt_id, "url": "https://example.com/reset"},
        )

    data = _text(content)
    assert data["test_type"] == "password_reset"


# -- test_ai -------------------------------------------------------------------


async def test_ai(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("ai_prompt_injection"))
    with patch("boba.mcp.tools_vuln.vuln.test_ai", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_ai",
            {"hunt_id": hunt_id, "url": "https://example.com/chat", "param": "message"},
        )

    data = _text(content)
    assert data["test_type"] == "ai_prompt_injection"


# -- test_ai_conversation ------------------------------------------------------


async def test_ai_conversation(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _inject_mock_client(mcp_resources, hunt_id)

    mock_fn = AsyncMock(return_value=_vuln_result("ai_conversation"))
    with patch("boba.mcp.tools_vuln.vuln.test_ai_conversation", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_ai_conversation",
            {"hunt_id": hunt_id, "url": "https://example.com/api/chat"},
        )

    data = _text(content)
    assert data["test_type"] == "ai_conversation"


# -- session resolution --------------------------------------------------------


async def test_required_session_missing_raises(mcp_server, mcp_resources):
    """Tools that require a session raise when it doesn't exist."""
    hunt_id = await _create_hunt(mcp_server)
    _inject_mock_client(mcp_resources, hunt_id)

    with pytest.raises(Exception, match="not found"):
        await mcp_server.call_tool(
            "test_race",
            {
                "hunt_id": hunt_id,
                "url": "https://example.com/api/claim",
                "session_name": "nonexistent",
            },
        )


async def test_invalid_hunt_id_raises(mcp_server):
    """All vuln tools validate hunt_id."""
    with pytest.raises(Exception):
        await mcp_server.call_tool(
            "test_sqli",
            {"hunt_id": "bad_id_000000", "url": "https://example.com", "param": "q"},
        )


# -- serialization correctness ------------------------------------------------


async def test_vuln_result_serialization(mcp_server, mcp_resources):
    """VulnTestResult fields are correctly serialized."""
    hunt_id = await _create_hunt(mcp_server)
    _inject_mock_client(mcp_resources, hunt_id)

    result = VulnTestResult(
        test_type="sqli",
        vulnerable=False,
        confidence=Confidence.POSSIBLE,
        title="No SQLi found",
        description="All payloads returned identical responses",
        severity=Severity.INFO,
        evidence=[],
        request_ids=[1, 2, 3],
        recommendations=["Monitor for future changes"],
        waf_detected=True,
    )
    mock_fn = AsyncMock(return_value=result)
    with patch("boba.mcp.tools_vuln.vuln.test_sqli", mock_fn):
        content, _ = await mcp_server.call_tool(
            "test_sqli",
            {"hunt_id": hunt_id, "url": "https://example.com/search", "param": "q"},
        )

    data = _text(content)
    assert data["vulnerable"] is False
    assert data["confidence"] == "possible"
    assert data["waf_detected"] is True
    assert data["request_ids"] == [1, 2, 3]
    assert data["recommendations"] == ["Monitor for future changes"]
