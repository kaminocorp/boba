"""Hunt CRUD operations mixin."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from boba.core.errors import HuntNotFoundError
from boba.core.models import (
    Hunt,
    HuntStatus,
    ScopeAction,
    ScopeConfig,
    ScopeRule,
    ScopeRuleType,
)

from boba.core.context._helpers import _now

logger = logging.getLogger(__name__)


class HuntCrudMixin:
    """Hunt create/read/update operations."""

    _conn: sqlite3.Connection

    def create_hunt(self, hunt: Hunt) -> str:
        now = _now()
        scope_json = json.dumps(
            {
                "rules": [
                    {"pattern": r.pattern, "type": r.rule_type.value, "action": r.action.value}
                    for r in hunt.scope.rules
                ]
            }
        )
        with self._conn:
            self._conn.execute(
                "INSERT INTO hunts (id, name, status, scope_json, config_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    hunt.id,
                    hunt.name,
                    hunt.status.value,
                    scope_json,
                    json.dumps(hunt.config),
                    now,
                    now,
                ),
            )
            for rule in hunt.scope.rules:
                self._conn.execute(
                    "INSERT OR IGNORE INTO scope_rules (hunt_id, pattern, rule_type, action) VALUES (?, ?, ?, ?)",
                    (hunt.id, rule.pattern, rule.rule_type.value, rule.action.value),
                )
        return hunt.id

    def get_hunt(self, hunt_id: str) -> Hunt:
        row = self._conn.execute("SELECT * FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
        if not row:
            raise HuntNotFoundError(f"Hunt '{hunt_id}' not found")
        return self._row_to_hunt(row)

    def list_hunts(self) -> list[Hunt]:
        rows = self._conn.execute("SELECT * FROM hunts ORDER BY created_at DESC").fetchall()
        return [self._row_to_hunt(r) for r in rows]

    # Valid state transitions: active→paused, active→completed, paused→active, paused→completed
    _VALID_TRANSITIONS: dict[HuntStatus, frozenset[HuntStatus]] = {
        HuntStatus.ACTIVE: frozenset({HuntStatus.PAUSED, HuntStatus.COMPLETED}),
        HuntStatus.PAUSED: frozenset({HuntStatus.ACTIVE, HuntStatus.COMPLETED}),
        HuntStatus.COMPLETED: frozenset(),  # terminal state
    }

    def update_hunt_status(self, hunt_id: str, status: HuntStatus) -> None:
        hunt = self.get_hunt(hunt_id)  # raises if not found
        current = HuntStatus(hunt.status) if isinstance(hunt.status, str) else hunt.status
        allowed = self._VALID_TRANSITIONS.get(current, frozenset())
        if status not in allowed:
            raise ValueError(
                f"Cannot transition hunt '{hunt_id}' from {current.value} to {status.value}. "
                f"Allowed transitions: {', '.join(s.value for s in sorted(allowed, key=lambda s: s.value)) or 'none (terminal state)'}"
            )
        self._conn.execute(
            "UPDATE hunts SET status = ?, updated_at = ? WHERE id = ?",
            (status.value, _now(), hunt_id),
        )
        self._conn.commit()

    def _row_to_hunt(self, row: sqlite3.Row) -> Hunt:
        try:
            scope_data = json.loads(row["scope_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("Malformed scope_json for hunt %s: %s", row["id"], exc)
            scope_data = {"rules": []}
        rules = [
            ScopeRule(
                pattern=r["pattern"],
                rule_type=ScopeRuleType(r["type"]),
                action=ScopeAction(r["action"]),
            )
            for r in scope_data.get("rules", [])
        ]
        try:
            config = json.loads(row["config_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("Malformed config_json for hunt %s: %s", row["id"], exc)
            config = {}
        return Hunt(
            id=row["id"],
            name=row["name"],
            status=HuntStatus(row["status"]),
            scope=ScopeConfig(rules=rules),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            config=config,
        )
