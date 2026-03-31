"""Shared test fixtures."""

from __future__ import annotations

import tempfile

import pytest

from boba.core.context import HuntContext
from boba.core.hunt import HuntManager
from boba.core.models import (
    Hunt,
    HuntStatus,
    ScopeAction,
    ScopeConfig,
    ScopeRule,
    ScopeRuleType,
)
from boba.core.scope import ScopeEngine


@pytest.fixture
def tmp_db(tmp_path):
    """Path to a temporary SQLite database."""
    return str(tmp_path / "test.db")


@pytest.fixture
def context(tmp_db):
    """HuntContext backed by a temp database."""
    ctx = HuntContext(tmp_db)
    yield ctx
    ctx.close()


@pytest.fixture
def sample_scope_config():
    """Scope config matching *.example.com, excluding internal.example.com."""
    return ScopeConfig(
        rules=[
            ScopeRule("*.example.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
            ScopeRule("example.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
            ScopeRule("internal.example.com", ScopeRuleType.DOMAIN, ScopeAction.EXCLUDE),
        ]
    )


@pytest.fixture
def scope_engine(sample_scope_config):
    """ScopeEngine with the sample config."""
    return ScopeEngine(sample_scope_config)


@pytest.fixture
def manager(tmp_db):
    """HuntManager with a temp database."""
    mgr = HuntManager(db_path=tmp_db)
    yield mgr
    mgr.close_context()


@pytest.fixture
def sample_hunt(manager, sample_scope_config):
    """A pre-created hunt with sample scope."""
    return manager.create(name="Test Hunt", scope=sample_scope_config)
