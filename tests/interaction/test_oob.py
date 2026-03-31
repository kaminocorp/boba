"""Tests for OOBManager."""

from __future__ import annotations

import pytest

from boba.core.errors import OOBError
from boba.core.models import Hunt, ScopeConfig
from boba.interaction.oob import OOBManager


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="oob_test_0001", name="OOB Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


@pytest.fixture
async def oob(context, hunt_id):
    mgr = OOBManager(context, hunt_id)
    await mgr.start()  # Uses fallback client since interactsh-py isn't installed
    yield mgr
    await mgr.stop()


class TestOOBLifecycle:
    @pytest.mark.asyncio
    async def test_start_uses_fallback(self, context, hunt_id):
        mgr = OOBManager(context, hunt_id)
        await mgr.start()
        # Should use fallback client
        assert mgr._client is not None
        await mgr.stop()
        assert mgr._client is None

    @pytest.mark.asyncio
    async def test_create_listener_before_start_raises(self, context, hunt_id):
        mgr = OOBManager(context, hunt_id)
        with pytest.raises(OOBError, match="not started"):
            await mgr.create_listener("test")


class TestCreateListener:
    @pytest.mark.asyncio
    async def test_create_returns_domain(self, oob):
        domain = await oob.create_listener(
            purpose="blind_ssrf",
            target_url="https://x.com/proxy",
            parameter="url",
        )
        assert ".oast.local" in domain
        assert len(domain) > 10

    @pytest.mark.asyncio
    async def test_listener_persisted_to_db(self, oob, context, hunt_id):
        await oob.create_listener(purpose="blind_xss")
        listeners = context.get_oob_listeners(hunt_id)
        assert len(listeners) == 1
        assert listeners[0]["purpose"] == "blind_xss"

    @pytest.mark.asyncio
    async def test_multiple_listeners_unique(self, oob):
        d1 = await oob.create_listener(purpose="test1")
        d2 = await oob.create_listener(purpose="test2")
        assert d1 != d2


class TestPayloadURL:
    @pytest.mark.asyncio
    async def test_http_url(self, oob):
        domain = await oob.create_listener(purpose="test")
        url = oob.get_payload_url(domain, protocol="http")
        assert url.startswith("http://")
        assert domain in url

    @pytest.mark.asyncio
    async def test_https_url(self, oob):
        domain = await oob.create_listener(purpose="test")
        url = oob.get_payload_url(domain, protocol="https")
        assert url.startswith("https://")


class TestPoll:
    @pytest.mark.asyncio
    async def test_poll_returns_empty_with_fallback(self, oob):
        """Fallback client has no real callbacks — should timeout and return empty."""
        results = await oob.poll(timeout_seconds=1, poll_interval=0.5)
        assert results == []

    @pytest.mark.asyncio
    async def test_check_all_returns_dict(self, oob):
        result = await oob.check_all()
        assert isinstance(result, dict)
