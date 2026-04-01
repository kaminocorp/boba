"""Tests for HttpClient."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from boba.core.models import FuzzAttackType, Hunt, ScopeConfig
from boba.interaction.history import HttpHistorySink
from boba.interaction.http import HttpClient


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="http_test_001", name="HTTP Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


@pytest.fixture
def sink(context, hunt_id, tmp_path):
    s = HttpHistorySink(context, hunt_id)
    s._body_dir = tmp_path / "bodies"
    s._body_dir.mkdir()
    return s


@pytest.fixture
def client(sink):
    """Create HttpClient. The persistent client is used for requests."""
    return HttpClient(sink)


def _mock_response(
    status_code=200,
    headers=None,
    content=b"ok",
    text="ok",
    url="https://example.com/",
    history=None,
):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {"content-type": "text/plain"}
    resp.content = content
    resp.text = text
    resp.url = url
    resp.history = history or []
    return resp


class TestRequest:
    @pytest.mark.asyncio
    async def test_basic_get(self, client, sink):
        mock_resp = _mock_response(status_code=200, content=b'{"ok": true}', text='{"ok": true}')
        client._client.request = AsyncMock(return_value=mock_resp)

        resp = await client.request(
            method="GET",
            url="https://example.com/api",
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 200
        assert resp.request_id > 0
        assert resp.body == b'{"ok": true}'

        # Verify persisted to history
        record = sink.get(resp.request_id)
        assert record is not None
        assert record["method"] == "GET"

    @pytest.mark.asyncio
    async def test_post_with_body(self, client, sink):
        mock_resp = _mock_response(status_code=201, content=b'{"id": 1}', text='{"id": 1}')
        client._client.request = AsyncMock(return_value=mock_resp)

        resp = await client.request(
            method="POST",
            url="https://example.com/api/users",
            headers={"Content-Type": "application/json"},
            body='{"name": "test"}',
        )
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_redirect_chain(self, client):
        redirect_resp = MagicMock()
        redirect_resp.url = "https://example.com/login"
        mock_resp = _mock_response(url="https://example.com/dashboard", history=[redirect_resp])
        client._client.request = AsyncMock(return_value=mock_resp)

        resp = await client.request(method="GET", url="https://example.com/login")
        assert resp.redirect_chain == ["https://example.com/login"]


class TestReplay:
    @pytest.mark.asyncio
    async def test_replay_from_history(self, client, sink):
        # First, insert a record directly
        rid = sink.record(
            method="GET",
            url="https://example.com/api/users/123",
            request_headers={"Authorization": "Bearer tok_a"},
            request_body=None,
            status_code=200,
            response_headers={"content-type": "application/json"},
            response_body=b'{"id": 123}',
            elapsed_ms=50.0,
            source="http_client",
        )

        mock_resp = _mock_response(status_code=200, content=b'{"id": 123}', text='{"id": 123}')
        client._client.request = AsyncMock(return_value=mock_resp)

        resp = await client.replay(
            rid,
            modifications={
                "headers": {"Authorization": "Bearer tok_b"},
            },
        )
        assert resp.status_code == 200

        # Should be linked to parent
        record = sink.get(resp.request_id)
        assert record["parent_request_id"] == rid
        assert record["source"] == "replay"

    @pytest.mark.asyncio
    async def test_replay_nonexistent_raises(self, client):
        with pytest.raises(ValueError, match="not found"):
            await client.replay(99999)


class TestCompare:
    @pytest.mark.asyncio
    async def test_identical_responses(self, client, sink):
        rid_a = sink.record(
            method="GET",
            url="https://x.com/api",
            request_headers={},
            request_body=None,
            status_code=200,
            response_headers={"content-type": "text/plain"},
            response_body=b"same",
            elapsed_ms=10.0,
        )
        rid_b = sink.record(
            method="GET",
            url="https://x.com/api",
            request_headers={},
            request_body=None,
            status_code=200,
            response_headers={"content-type": "text/plain"},
            response_body=b"same",
            elapsed_ms=12.0,
        )
        result = await client.compare(rid_a, rid_b)
        assert result.status_match is True
        assert result.body_diff_summary == "identical"

    @pytest.mark.asyncio
    async def test_different_responses(self, client, sink):
        rid_a = sink.record(
            method="GET",
            url="https://x.com/api",
            request_headers={},
            request_body=None,
            status_code=200,
            response_headers={"content-type": "text/plain"},
            response_body=b"user A data",
            elapsed_ms=10.0,
        )
        rid_b = sink.record(
            method="GET",
            url="https://x.com/api",
            request_headers={},
            request_body=None,
            status_code=403,
            response_headers={"content-type": "text/plain"},
            response_body=b"forbidden",
            elapsed_ms=5.0,
        )
        result = await client.compare(rid_a, rid_b)
        assert result.status_match is False
        assert result.status_a == 200
        assert result.status_b == 403
        assert "differ" in result.body_diff_summary


class TestFuzzBaseline:
    """Fuzz baseline must strip marker characters, not send them to the server."""

    @pytest.mark.asyncio
    async def test_baseline_strips_markers(self, client):
        """The baseline request should have markers replaced with empty strings."""
        captured_urls: list[str] = []
        mock_resp = _mock_response(status_code=200, content=b"ok", text="ok")

        async def _capture(**kwargs):
            captured_urls.append(kwargs.get("url", ""))
            return mock_resp

        client._client.request = _capture

        await client.fuzz(
            method="GET",
            url="https://example.com/api?id=§id§&name=§name§",
            positions=["id", "name"],
            payloads={"id": ["1"], "name": ["test"]},
            attack_type=FuzzAttackType.SNIPER,
        )

        # First request is the baseline — markers should be stripped
        assert len(captured_urls) >= 1
        baseline_url = captured_urls[0]
        assert "§" not in baseline_url
        assert baseline_url == "https://example.com/api?id=&name="


class TestFuzzCombinations:
    """Test combination generation without network calls."""

    def test_sniper(self, client):
        combos = client._generate_combinations(
            positions=["user", "pass"],
            payloads={"user": ["admin", "root"], "pass": ["123"]},
            attack_type=FuzzAttackType.SNIPER,
        )
        # Sniper: test each position independently
        assert len(combos) == 3  # 2 user payloads + 1 pass payload
        assert combos[0] == {"user": "admin", "pass": ""}
        assert combos[1] == {"user": "root", "pass": ""}
        assert combos[2] == {"user": "", "pass": "123"}

    def test_battering_ram(self, client):
        combos = client._generate_combinations(
            positions=["a", "b"],
            payloads={"a": ["x", "y"]},
            attack_type=FuzzAttackType.BATTERING_RAM,
        )
        assert len(combos) == 2
        assert combos[0] == {"a": "x", "b": "x"}
        assert combos[1] == {"a": "y", "b": "y"}

    def test_pitchfork(self, client):
        combos = client._generate_combinations(
            positions=["user", "pass"],
            payloads={"user": ["admin", "root"], "pass": ["pass1", "pass2"]},
            attack_type=FuzzAttackType.PITCHFORK,
        )
        assert len(combos) == 2
        assert combos[0] == {"user": "admin", "pass": "pass1"}
        assert combos[1] == {"user": "root", "pass": "pass2"}

    def test_cluster_bomb(self, client):
        combos = client._generate_combinations(
            positions=["user", "pass"],
            payloads={"user": ["admin", "root"], "pass": ["1", "2"]},
            attack_type=FuzzAttackType.CLUSTER_BOMB,
        )
        # Cartesian product: 2 × 2 = 4
        assert len(combos) == 4
        assert {"user": "admin", "pass": "1"} in combos
        assert {"user": "root", "pass": "2"} in combos
