"""OOBManager — Interactsh integration for blind vulnerability detection."""

from __future__ import annotations

import asyncio
import logging
import secrets
import string
import time
from typing import Any

from boba.core.context import HuntContext
from boba.core.errors import OOBError

logger = logging.getLogger(__name__)


class OOBManager:
    """Manages out-of-band listeners for detecting blind vulnerabilities.

    Uses Interactsh to generate unique callback domains. Each listener
    correlates back to the exact injection point (target URL + parameter).
    """

    def __init__(self, hunt_context: HuntContext, hunt_id: str):
        self._context = hunt_context
        self._hunt_id = hunt_id
        self._client: Any = None
        self._listeners: dict[str, dict[str, Any]] = {}

    async def start(self) -> None:
        """Initialize Interactsh client."""
        try:
            from interactsh import InteractshClient

            self._client = InteractshClient()
            await self._client.register()
        except ImportError:
            # Fall back to a simple mock mode for environments without interactsh
            logger.warning(
                "interactsh package not installed — OOB detection disabled. "
                "Blind SSRF/XSS tests will not detect callbacks. "
                "Install with: pip install interactsh"
            )
            self._client = _FallbackOOBClient()
        except Exception as e:
            raise OOBError(f"Failed to initialize Interactsh: {e}")

    async def stop(self) -> None:
        """Deregister and cleanup."""
        if self._client and hasattr(self._client, "deregister"):
            try:
                await self._client.deregister()
            except Exception as exc:
                logger.debug("Error deregistering OOB client: %s", exc)
        self._client = None
        self._listeners.clear()

    async def __aenter__(self) -> OOBManager:
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.stop()

    async def create_listener(
        self,
        purpose: str,
        target_url: str | None = None,
        parameter: str | None = None,
        test_payload: str | None = None,
    ) -> str:
        """Create a unique callback listener. Returns the callback domain."""
        if not self._client:
            raise OOBError("OOB manager not started. Call start() first.")

        if hasattr(self._client, "generate_domain"):
            callback_domain = self._client.generate_domain()
        else:
            # Fallback generates a random subdomain
            callback_domain = self._client.get_domain()

        if not callback_domain or "." not in callback_domain:
            raise OOBError(f"Invalid callback domain from OOB client: {callback_domain!r}")
        listener_id = callback_domain.split(".")[0]
        if not listener_id:
            raise OOBError(f"Empty listener ID extracted from domain: {callback_domain!r}")

        self._listeners[listener_id] = {
            "callback_domain": callback_domain,
            "purpose": purpose,
            "target_url": target_url,
            "parameter": parameter,
            "test_payload": test_payload,
        }

        self._context.insert_oob_listener(
            self._hunt_id,
            {
                "listener_id": listener_id,
                "callback_domain": callback_domain,
                "purpose": purpose,
                "target_url": target_url,
                "parameter": parameter,
                "test_payload": test_payload,
            },
        )

        return callback_domain

    def get_payload_url(self, callback_domain: str, protocol: str = "http") -> str:
        """Return full URL for injection."""
        return f"{protocol}://{callback_domain}"

    async def poll(
        self,
        listener_id: str | None = None,
        timeout_seconds: int = 30,
        poll_interval: float = 2.0,
    ) -> list[dict[str, Any]]:
        """Poll for interactions on a specific or all listeners."""
        if not self._client:
            raise OOBError("OOB manager not started.")

        all_interactions: list[dict[str, Any]] = []
        deadline = time.monotonic() + timeout_seconds

        while time.monotonic() < deadline:
            try:
                if hasattr(self._client, "poll"):
                    raw = await self._client.poll()
                else:
                    raw = self._client.get_interactions()

                if raw:
                    for interaction in raw:
                        entry = {
                            "type": interaction.get("protocol", "unknown"),
                            "remote_address": interaction.get("remote-address", ""),
                            "timestamp": interaction.get("timestamp", ""),
                            "raw_request": interaction.get("raw-request", ""),
                            "full_id": interaction.get("full-id", ""),
                        }
                        # Match to listener — use startswith since Interactsh
                        # prefixes the full interaction ID with the listener ID
                        full_id = entry.get("full_id", "")
                        for lid, info in self._listeners.items():
                            if lid and full_id.startswith(lid):
                                entry["listener_id"] = lid
                                entry["purpose"] = info["purpose"]
                                entry["target_url"] = info["target_url"]
                                entry["parameter"] = info["parameter"]
                                break

                        if listener_id is None or entry.get("listener_id") == listener_id:
                            all_interactions.append(entry)

                    if all_interactions:
                        break

            except Exception as exc:
                logger.debug("Error polling OOB interactions: %s", exc)

            await asyncio.sleep(poll_interval)

        # Persist interactions — fetch listeners once, index by ID
        if all_interactions:
            existing_listeners = {
                rec["listener_id"]: rec for rec in self._context.get_oob_listeners(self._hunt_id)
            }
            for interaction in all_interactions:
                lid = interaction.get("listener_id")
                if lid and lid in existing_listeners:
                    prev = existing_listeners[lid].get("interactions", [])
                    # Deduplicate by full_id to avoid appending the same
                    # interaction across multiple poll() calls.
                    seen_ids = {p.get("full_id") for p in prev if p.get("full_id")}
                    if interaction.get("full_id") not in seen_ids:
                        prev.append(interaction)
                    self._context.update_oob_interactions(self._hunt_id, lid, prev)

        return all_interactions

    async def check_all(self) -> dict[str, list[dict]]:
        """Poll all active listeners, return results grouped by listener_id."""
        interactions = await self.poll(timeout_seconds=5, poll_interval=1.0)
        grouped: dict[str, list[dict]] = {}
        for i in interactions:
            lid = i.get("listener_id", "unknown")
            grouped.setdefault(lid, []).append(i)
        return grouped


class _FallbackOOBClient:
    """Simple fallback when Interactsh is not available.

    Generates random domains for testing purposes.
    Does not actually receive callbacks — useful for unit tests
    and environments where Interactsh isn't installed.
    """

    def __init__(self):
        self._base_domain = "oast.local"

    async def register(self) -> None:
        """No-op registration for fallback client."""

    async def deregister(self) -> None:
        """No-op deregistration for fallback client."""

    def get_domain(self) -> str:
        rand = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12))
        return f"{rand}.{self._base_domain}"

    def get_interactions(self) -> list[dict]:
        return []
