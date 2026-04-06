"""Managed resource pool shared across MCP tool calls."""

from __future__ import annotations

import logging
from pathlib import Path

from boba.core.context import HuntContext
from boba.core.hunt import HuntManager
from boba.core.models import Hunt
from boba.core.scope import ScopeEngine

logger = logging.getLogger(__name__)


class ServerResources:
    """Holds long-lived resources that persist across MCP tool calls.

    Resources are created lazily and cached per-hunt (or globally for
    the browser).  ``shutdown()`` tears down everything.
    """

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir
        self._manager: HuntManager | None = None
        # Phase 3: per-hunt interaction resources
        self._http_clients: dict[str, object] = {}
        self._session_managers: dict[str, object] = {}
        self._oob_managers: dict[str, object] = {}
        self._browser: object | None = None

    # -- lazy accessors (Phase 1-2) -------------------------------------------

    def get_manager(self) -> HuntManager:
        """Return (or create) the shared :class:`HuntManager`."""
        if self._manager is None:
            db_path = self._data_dir / "boba.db"
            self._manager = HuntManager(db_path=db_path)
        return self._manager

    def get_context(self) -> HuntContext:
        """Return the shared :class:`HuntContext` (via the manager)."""
        return self.get_manager().context

    def get_hunt(self, hunt_id: str) -> Hunt:
        """Shorthand — fetches a hunt or raises ``HuntNotFoundError``."""
        return self.get_manager().get(hunt_id)

    def get_scope_engine(self, hunt: Hunt) -> ScopeEngine:
        """Build a :class:`ScopeEngine` from a hunt's scope config."""
        return ScopeEngine(hunt.scope)

    # -- Phase 3: interaction resources ---------------------------------------

    def get_http_client(self, hunt_id: str):
        """Return (or create) an :class:`HttpClient` for *hunt_id*."""
        from boba.interaction.history import HttpHistorySink
        from boba.interaction.http import HttpClient

        if hunt_id not in self._http_clients:
            self.get_hunt(hunt_id)  # validate
            sink = HttpHistorySink(self.get_context(), hunt_id)
            self._http_clients[hunt_id] = HttpClient(sink)
        return self._http_clients[hunt_id]

    def get_session_manager(self, hunt_id: str):
        """Return (or create) a :class:`SessionManager` for *hunt_id*."""
        from boba.interaction.session import SessionManager

        if hunt_id not in self._session_managers:
            self.get_hunt(hunt_id)  # validate
            self._session_managers[hunt_id] = SessionManager(self.get_context(), hunt_id)
        return self._session_managers[hunt_id]

    async def get_browser(self):
        """Return (or create and start) the shared :class:`BrowserManager`."""
        from boba.core.models import BrowserConfig
        from boba.interaction.browser import BrowserManager
        from boba.interaction.history import HttpHistorySink

        if self._browser is None:
            # Browser needs a sink — use a generic one with empty hunt_id;
            # individual tool calls provide their own hunt context.
            sink = HttpHistorySink(self.get_context(), "")
            config = BrowserConfig(headless=True)
            self._browser = BrowserManager(config, sink)
            await self._browser.start()
        return self._browser

    def get_oob_manager(self, hunt_id: str):
        """Return (or create) an :class:`OOBManager` for *hunt_id*.

        Note: the caller must ``await oob.start()`` if not already started.
        """
        from boba.interaction.oob import OOBManager

        if hunt_id not in self._oob_managers:
            self.get_hunt(hunt_id)  # validate
            self._oob_managers[hunt_id] = OOBManager(self.get_context(), hunt_id)
        return self._oob_managers[hunt_id]

    # -- lifecycle ------------------------------------------------------------

    async def shutdown(self) -> None:
        """Release all managed resources.  Called on server stop."""
        for hunt_id, client in self._http_clients.items():
            try:
                await client.close()
            except Exception:
                logger.debug("Error closing HTTP client for hunt %s", hunt_id, exc_info=True)
        self._http_clients.clear()

        if self._browser is not None:
            try:
                await self._browser.stop()
            except Exception:
                logger.debug("Error stopping browser", exc_info=True)
            self._browser = None

        for hunt_id, oob in self._oob_managers.items():
            try:
                await oob.stop()
            except Exception:
                logger.debug("Error stopping OOB manager for hunt %s", hunt_id, exc_info=True)
        self._oob_managers.clear()

        self._session_managers.clear()

        if self._manager is not None:
            self._manager.close_context()
            self._manager = None
