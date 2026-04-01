"""Tests for HuntManager lifecycle and persistence."""

from __future__ import annotations

import pytest

from boba.core.errors import HuntNotFoundError
from boba.core.hunt import HuntManager
from boba.core.models import HuntStatus


class TestHuntCreation:
    def test_create_hunt_basic(self, manager):
        hunt = manager.create(name="basic")
        assert hunt.name == "basic"
        assert hunt.status == HuntStatus.ACTIVE
        assert hunt.id  # non-empty

    def test_create_hunt_with_scope(self, manager, sample_scope_config):
        hunt = manager.create(name="scoped", scope=sample_scope_config)
        assert hunt.status == HuntStatus.ACTIVE
        assert len(hunt.scope.rules) == len(sample_scope_config.rules)
        # Verify the rules survived the round-trip
        retrieved = manager.get(hunt.id)
        assert len(retrieved.scope.rules) == len(sample_scope_config.rules)
        patterns = {r.pattern for r in retrieved.scope.rules}
        assert "*.example.com" in patterns
        assert "internal.example.com" in patterns

    def test_create_hunt_with_scope_yaml(self, tmp_path):
        yaml_file = tmp_path / "scope.yaml"
        yaml_file.write_text(
            "rules:\n"
            "  - pattern: '*.target.com'\n"
            "    type: domain\n"
            "    action: include\n"
            "  - pattern: 'admin.target.com'\n"
            "    type: domain\n"
            "    action: exclude\n"
        )
        db_path = tmp_path / "hunt.db"
        mgr = HuntManager(db_path=db_path)
        try:
            hunt = mgr.create(name="yaml-hunt", scope_yaml=str(yaml_file))
            assert hunt.status == HuntStatus.ACTIVE
            assert len(hunt.scope.rules) == 2
            patterns = {r.pattern for r in hunt.scope.rules}
            assert "*.target.com" in patterns
            assert "admin.target.com" in patterns
        finally:
            mgr.close_context()

    def test_create_hunt_with_scope_yaml_empty_file(self, tmp_path):
        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text("")
        db_path = tmp_path / "hunt.db"
        mgr = HuntManager(db_path=db_path)
        try:
            with pytest.raises(ValueError, match="expected a mapping"):
                mgr.create(name="empty-yaml", scope_yaml=str(yaml_file))
        finally:
            mgr.close_context()

    def test_hunt_config_persisted(self, manager):
        config = {"threads": 10, "timeout": 30, "tags": ["web", "api"]}
        hunt = manager.create(name="configured", config=config)
        retrieved = manager.get(hunt.id)
        assert retrieved.config == config


class TestHuntRetrieval:
    def test_get_hunt(self, manager):
        created = manager.create(name="retrievable")
        retrieved = manager.get(created.id)
        assert retrieved.id == created.id
        assert retrieved.name == "retrievable"

    def test_get_nonexistent_hunt(self, manager):
        with pytest.raises(HuntNotFoundError):
            manager.get("nonexistent_id_12345")

    def test_list_hunts_empty(self, manager):
        hunts = manager.list_hunts()
        assert hunts == []

    def test_list_hunts_multiple(self, manager):
        names = ["alpha", "bravo", "charlie"]
        for name in names:
            manager.create(name=name)
        hunts = manager.list_hunts()
        assert len(hunts) == 3
        listed_names = {h.name for h in hunts}
        assert listed_names == set(names)


class TestHuntStateTransitions:
    def test_pause_hunt(self, manager):
        hunt = manager.create(name="pausable")
        paused = manager.pause(hunt.id)
        assert paused.status == HuntStatus.PAUSED

    def test_resume_hunt(self, manager):
        hunt = manager.create(name="resumable")
        manager.pause(hunt.id)
        resumed = manager.resume(hunt.id)
        assert resumed.status == HuntStatus.ACTIVE

    def test_close_hunt(self, manager):
        hunt = manager.create(name="closable")
        closed = manager.close(hunt.id)
        assert closed.status == HuntStatus.COMPLETED

    def test_close_completed_raises(self, manager):
        hunt = manager.create(name="terminal")
        manager.close(hunt.id)
        with pytest.raises(ValueError, match="terminal state"):
            manager.pause(hunt.id)
        with pytest.raises(ValueError, match="terminal state"):
            manager.resume(hunt.id)
        with pytest.raises(ValueError, match="terminal state"):
            manager.close(hunt.id)


class TestHuntStats:
    def test_stats_empty_hunt(self, manager):
        hunt = manager.create(name="empty-stats")
        stats = manager.stats(hunt.id)
        assert isinstance(stats, dict)
        # All counts should be zero for a fresh hunt
        for value in stats.values():
            assert value == 0
