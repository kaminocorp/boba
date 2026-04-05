"""Hunt lifecycle management."""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

from boba.core.config import get_db_path
from boba.core.context import HuntContext
from boba.core.models import Hunt, HuntStatus, ScopeConfig
from boba.core.scope import ScopeEngine

_MAX_ID_RETRIES = 3


class HuntManager:
    """Create, query, and manage hunts."""

    def __init__(self, db_path: str | Path | None = None):
        self._db_path = str(db_path or get_db_path())
        self._context = HuntContext(self._db_path)

    @property
    def context(self) -> HuntContext:
        return self._context

    def create(
        self,
        name: str,
        scope: ScopeConfig | None = None,
        scope_yaml: str | Path | None = None,
        config: dict | None = None,
    ) -> Hunt:
        """Create a new hunt with scope and optional config."""
        if scope_yaml:
            engine = ScopeEngine.from_yaml(scope_yaml)
            scope = engine.config
        if scope is None:
            scope = ScopeConfig()

        for _ in range(_MAX_ID_RETRIES):
            hunt = Hunt(
                id=uuid.uuid4().hex[:12],
                name=name,
                scope=scope,
                config=config or {},
            )
            try:
                self._context.create_hunt(hunt)
                return hunt
            except sqlite3.IntegrityError:
                continue
        raise RuntimeError("failed to generate unique hunt ID after retries")

    def get(self, hunt_id: str) -> Hunt:
        return self._context.get_hunt(hunt_id)

    def list_hunts(self) -> list[Hunt]:
        return self._context.list_hunts()

    def pause(self, hunt_id: str) -> Hunt:
        self._context.update_hunt_status(hunt_id, HuntStatus.PAUSED)
        return self.get(hunt_id)

    def resume(self, hunt_id: str) -> Hunt:
        self._context.update_hunt_status(hunt_id, HuntStatus.ACTIVE)
        return self.get(hunt_id)

    def close(self, hunt_id: str) -> Hunt:
        self._context.update_hunt_status(hunt_id, HuntStatus.COMPLETED)
        return self.get(hunt_id)

    def stats(self, hunt_id: str) -> dict:
        self.get(hunt_id)  # raises if not found
        return self._context.get_hunt_stats(hunt_id)

    def close_context(self) -> None:
        self._context.close()

    def __enter__(self) -> HuntManager:
        return self

    def __exit__(self, *args) -> None:
        self.close_context()
