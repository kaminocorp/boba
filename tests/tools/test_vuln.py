"""Tests for vulnerability testing tools — mocked HTTP client."""

from __future__ import annotations


import pytest

from boba.core.models import (
    AuthMethod,
    Confidence,
    Hunt,
    HttpResponse,
    ScopeConfig,
    SessionState,
    Severity,
)
from boba.interaction.history import HttpHistorySink
from boba.interaction.http import HttpClient
from boba.tools import vuln


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="vuln_test_001", name="Vuln Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


@pytest.fixture
def sink(context, hunt_id, tmp_path):
    s = HttpHistorySink(context, hunt_id)
    s._body_dir = tmp_path / "bodies"
    s._body_dir.mkdir()
    return s


@pytest.fixture
def session_a():
    return SessionState(
        name="user_a",
        target_url="https://app.example.com",
        auth_method=AuthMethod.COOKIE,
        cookies={"session": "tok_a"},
        headers={"Cookie": "session=tok_a"},
    )


@pytest.fixture
def session_b():
    return SessionState(
        name="user_b",
        target_url="https://app.example.com",
        auth_method=AuthMethod.COOKIE,
        cookies={"session": "tok_b"},
        headers={"Cookie": "session=tok_b"},
    )


def _make_response(status_code, body_text, request_id=1):
    return HttpResponse(
        request_id=request_id,
        status_code=status_code,
        headers={"content-type": "text/html"},
        body=body_text.encode(),
        body_text=body_text,
        elapsed_ms=50.0,
    )


class TestIDOR:
    @pytest.mark.asyncio
    async def test_idor_confirmed(self, sink, session_a, session_b):
        """User B gets same data as User A, but unauthenticated is denied → IDOR."""
        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            if "user_a" in (kwargs.get("session_name") or ""):
                return _make_response(200, '{"id": 123, "name": "Alice"}', call_count)
            elif "user_b" in (kwargs.get("session_name") or ""):
                return _make_response(200, '{"id": 123, "name": "Alice"}', call_count)
            else:
                return _make_response(403, "Forbidden", call_count)

        client.request = mock_request
        result = await vuln.test_idor(
            client,
            session_a,
            session_b,
            endpoint="https://app.example.com/api/users/123",
        )
        assert result.vulnerable is True
        assert result.confidence == Confidence.CONFIRMED
        assert result.severity == Severity.HIGH
        assert len(result.request_ids) == 3

    @pytest.mark.asyncio
    async def test_idor_not_vulnerable(self, sink, session_a, session_b):
        """User B gets denied → no IDOR."""
        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            if "user_a" in (kwargs.get("session_name") or ""):
                return _make_response(200, '{"id": 123}', call_count)
            else:
                return _make_response(403, "Forbidden", call_count)

        client.request = mock_request
        result = await vuln.test_idor(
            client,
            session_a,
            session_b,
            endpoint="https://app.example.com/api/users/123",
        )
        assert result.vulnerable is False


class TestSSRF:
    @pytest.mark.asyncio
    async def test_ssrf_detected_via_metadata_confirmed(self, sink):
        """Full AWS metadata format in response → SSRF confirmed via regex."""
        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            url = kwargs.get("url", "")
            if "169.254.169.254" in url:
                return _make_response(
                    200,
                    'ami-0abcdef123456789\n"instanceId": "i-abc123"',
                    call_count,
                )
            return _make_response(200, "normal response", call_count)

        client.request = mock_request
        result = await vuln.test_ssrf(
            client,
            url="https://app.example.com/proxy",
            payloads=["http://169.254.169.254/latest/meta-data/"],
        )
        assert result.vulnerable is True
        assert result.confidence == Confidence.CONFIRMED

    @pytest.mark.asyncio
    async def test_ssrf_detected_via_metadata_likely(self, sink):
        """Cloud metadata substring match (no regex hit) → SSRF likely."""
        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            url = kwargs.get("url", "")
            if "169.254.169.254" in url:
                return _make_response(200, "instance-id hostname local-ipv4", call_count)
            return _make_response(200, "normal response", call_count)

        client.request = mock_request
        result = await vuln.test_ssrf(
            client,
            url="https://app.example.com/proxy",
            payloads=["http://169.254.169.254/latest/meta-data/"],
        )
        assert result.vulnerable is True
        assert result.confidence == Confidence.LIKELY

    @pytest.mark.asyncio
    async def test_ssrf_not_vulnerable(self, sink):
        """Normal responses for all payloads → no SSRF."""
        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            return _make_response(400, "Invalid URL", call_count)

        client.request = mock_request
        result = await vuln.test_ssrf(
            client,
            url="https://app.example.com/proxy",
            payloads=["http://127.0.0.1"],
        )
        assert result.vulnerable is False


class TestXSS:
    @pytest.mark.asyncio
    async def test_reflected_xss(self, sink):
        """Payload reflected unescaped in response → XSS confirmed."""
        from urllib.parse import unquote

        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            url = kwargs.get("url", "")
            # Server decodes URL params and reflects them (simulating reflected XSS)
            decoded_url = unquote(url)
            if "alert(1)" in decoded_url:
                return _make_response(200, "<p>Search: <script>alert(1)</script></p>", call_count)
            return _make_response(200, "<p>Search: safe</p>", call_count)

        client.request = mock_request
        result = await vuln.test_xss(
            client,
            url="https://app.example.com/search",
            params={"q": "test"},
            payloads=["<script>alert(1)</script>"],
        )
        assert result.vulnerable is True
        assert result.confidence == Confidence.CONFIRMED
        assert result.evidence[0]["type"] == "reflected"

    @pytest.mark.asyncio
    async def test_xss_partial_reflection(self, sink):
        """Payload inner content reflected but tags escaped → POSSIBLE XSS."""
        client = HttpClient(sink)
        call_count = 0
        # Use a longer inner content (≥16 chars) to avoid matching common JS snippets
        inner = "alert(document.cookie)"

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            return _make_response(200, f"<p>Search: {inner}</p>", call_count)

        client.request = mock_request
        result = await vuln.test_xss(
            client,
            url="https://app.example.com/search",
            params={"q": "test"},
            payloads=[f"<script>{inner}</script>"],
        )
        assert result.vulnerable is True
        assert result.confidence == Confidence.POSSIBLE
        assert result.evidence[0]["type"] == "partial_reflection"

    @pytest.mark.asyncio
    async def test_xss_not_vulnerable(self, sink):
        """Payload fully stripped from response → no XSS."""
        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            return _make_response(200, "<p>Search: no results found</p>", call_count)

        client.request = mock_request
        result = await vuln.test_xss(
            client,
            url="https://app.example.com/search",
            params={"q": "test"},
            payloads=["<script>alert(1)</script>"],
        )
        assert result.vulnerable is False


class TestSQLi:
    @pytest.mark.asyncio
    async def test_error_based_sqli(self, sink):
        """SQL error string in response → SQLi confirmed."""
        from urllib.parse import unquote

        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            url = kwargs.get("url", "")
            # Server decodes URL params — single quote triggers SQL error
            decoded_url = unquote(url)
            if "'" in decoded_url:
                return _make_response(
                    500,
                    "Error: You have an error in your SQL syntax near ''",
                    call_count,
                )
            return _make_response(200, "normal result", call_count)

        client.request = mock_request
        result = await vuln.test_sqli(
            client,
            url="https://app.example.com/api/items",
            params={"id": "1"},
            payloads=["'"],
        )
        assert result.vulnerable is True
        assert result.confidence == Confidence.CONFIRMED
        assert result.evidence[0]["type"] == "error_based"

    @pytest.mark.asyncio
    async def test_sqli_not_vulnerable(self, sink):
        """No SQL errors, same response for true/false → safe."""
        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            return _make_response(200, "same response always", call_count)

        client.request = mock_request
        result = await vuln.test_sqli(
            client,
            url="https://app.example.com/api/items",
            params={"id": "1"},
            payloads=["'"],
        )
        assert result.vulnerable is False


class TestAuth:
    @pytest.mark.asyncio
    async def test_no_auth_access(self, sink):
        """Endpoint accessible without any auth → auth bypass."""
        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            return _make_response(200, "admin panel", call_count)

        client.request = mock_request
        result = await vuln.test_auth(
            client,
            endpoint="https://app.example.com/admin/dashboard",
        )
        assert result.vulnerable is True
        assert result.confidence == Confidence.CONFIRMED

    @pytest.mark.asyncio
    async def test_auth_properly_enforced(self, sink):
        """Endpoint returns 401 without auth → properly protected."""
        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            if not kwargs.get("headers") or "Authorization" not in kwargs.get("headers", {}):
                return _make_response(401, "Unauthorized", call_count)
            return _make_response(200, "ok", call_count)

        client.request = mock_request
        result = await vuln.test_auth(
            client,
            endpoint="https://app.example.com/api/data",
        )
        assert result.vulnerable is False
