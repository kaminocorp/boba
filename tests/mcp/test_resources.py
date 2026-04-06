"""Tests for ServerResources lifecycle."""

from __future__ import annotations

import pytest

from boba.core.errors import HuntNotFoundError
from boba.mcp.resources import ServerResources


def test_get_manager_creates_lazily(tmp_path):
    res = ServerResources(data_dir=tmp_path)
    assert res._manager is None
    mgr = res.get_manager()
    assert mgr is not None
    assert res._manager is mgr
    res._manager.close_context()


def test_get_manager_returns_same_instance(tmp_path):
    res = ServerResources(data_dir=tmp_path)
    a = res.get_manager()
    b = res.get_manager()
    assert a is b
    res._manager.close_context()


def test_get_hunt_delegates_to_manager(tmp_path):
    res = ServerResources(data_dir=tmp_path)
    mgr = res.get_manager()
    hunt = mgr.create(name="test")
    fetched = res.get_hunt(hunt.id)
    assert fetched.name == "test"
    res._manager.close_context()


def test_get_hunt_raises_on_bad_id(tmp_path):
    res = ServerResources(data_dir=tmp_path)
    res.get_manager()  # init
    with pytest.raises(HuntNotFoundError):
        res.get_hunt("nonexistent")
    res._manager.close_context()


async def test_shutdown_closes_manager(tmp_path):
    res = ServerResources(data_dir=tmp_path)
    res.get_manager()
    await res.shutdown()
    assert res._manager is None


async def test_shutdown_idempotent(tmp_path):
    res = ServerResources(data_dir=tmp_path)
    await res.shutdown()  # no manager yet — should not error
    res.get_manager()
    await res.shutdown()
    await res.shutdown()
    assert res._manager is None


def test_db_file_created_in_data_dir(tmp_path):
    res = ServerResources(data_dir=tmp_path)
    res.get_manager()
    assert (tmp_path / "boba.db").exists()
    res._manager.close_context()
