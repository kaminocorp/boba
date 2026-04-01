"""SessionManager — authentication state persistence and application."""

from __future__ import annotations

import base64
import copy
from typing import Any

from boba.core.context import HuntContext
from boba.core.errors import SessionError
from boba.core.models import AuthMethod, SessionState


class SessionManager:
    """Manages named authentication sessions for a hunt.

    Sessions are serializable auth state (cookies, headers, tokens) that can
    be applied to either a browser context or an HTTP client. This enables
    the critical IDOR workflow: two sessions, same request, compare responses.
    """

    def __init__(self, hunt_context: HuntContext, hunt_id: str):
        self._context = hunt_context
        self._hunt_id = hunt_id
        # In-memory cache for fast access
        self._cache: dict[str, SessionState] = {}

    def create(
        self,
        name: str,
        target_url: str,
        auth_method: AuthMethod = AuthMethod.FORM,
    ) -> SessionState:
        """Create a new named session."""
        state = SessionState(
            name=name,
            target_url=target_url,
            auth_method=auth_method,
        )
        self._persist(state)
        self._cache[name] = state
        return state

    def login_bearer(self, session_name: str, token: str) -> SessionState:
        """Set a Bearer token on a session."""
        state = self._get_or_raise(session_name)
        state.auth_method = AuthMethod.BEARER
        state.tokens["access_token"] = token
        state.headers["Authorization"] = f"Bearer {token}"
        self._persist(state)
        return state

    def login_basic(self, session_name: str, username: str, password: str) -> SessionState:
        """Set HTTP Basic auth on a session."""
        state = self._get_or_raise(session_name)
        state.auth_method = AuthMethod.BASIC
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        state.headers["Authorization"] = f"Basic {encoded}"
        self._persist(state)
        return state

    def login_cookies(self, session_name: str, cookies: dict[str, str]) -> SessionState:
        """Inject raw cookies into a session."""
        state = self._get_or_raise(session_name)
        state.auth_method = AuthMethod.COOKIE
        state.cookies.update(cookies)
        self._persist(state)
        return state

    async def login_form(
        self,
        session_name: str,
        login_url: str,
        credentials: dict[str, str],
        browser: Any,
    ) -> SessionState:
        """Browser-based form login.

        1. Navigate to login_url in the session's browser context
        2. Fill form fields from credentials dict
        3. Submit form
        4. Capture resulting cookies + storage state
        5. Persist to sessions table
        """
        state = self._get_or_raise(session_name)

        # Apply current session state to browser
        await browser.apply_session(state)

        # Navigate to login page
        await browser.navigate(login_url, context_name=session_name)

        # Fill and submit the login form
        page = await browser.get_page(session_name)

        for field_name, value in credentials.items():
            # Try common selectors — escape field_name for CSS safety
            safe_name = field_name.replace("\\", "\\\\").replace("'", "\\'")
            filled = False
            for selector in [
                f"[name='{safe_name}']",
                f"#{safe_name}",
                f"[id='{safe_name}']",
            ]:
                try:
                    await page.fill(selector, value)
                    filled = True
                    break
                except Exception:
                    continue
            if not filled:
                raise SessionError(
                    f"Could not find form field '{field_name}' on {login_url}. "
                    f"Tried selectors: [name=], #id, [id=]"
                )

        # Submit — try various common patterns
        submitted = False
        for submit_selector in [
            "[type='submit']",
            "button[type='submit']",
            "input[type='submit']",
            "button:has-text('Log in')",
            "button:has-text('Sign in')",
            "button:has-text('Login')",
        ]:
            try:
                await page.click(submit_selector)
                submitted = True
                break
            except Exception:
                continue
        if not submitted:
            raise SessionError(
                f"Could not find submit button on {login_url}. "
                "Tried: [type='submit'], button, input, text patterns."
            )

        await page.wait_for_load_state("networkidle", timeout=30_000)

        # Capture auth state
        cookies_raw = await browser.get_cookies(session_name)
        state.cookies = {c["name"]: c["value"] for c in cookies_raw}
        state.storage_state = await browser.get_storage_state(session_name)
        state.auth_method = AuthMethod.FORM

        self._persist(state)
        return state

    def login_header(self, session_name: str, header_name: str, header_value: str) -> SessionState:
        """Set a custom auth header on a session."""
        state = self._get_or_raise(session_name)
        state.auth_method = AuthMethod.CUSTOM_HEADER
        state.headers[header_name] = header_value
        self._persist(state)
        return state

    def apply_to_headers(self, session_name: str) -> dict[str, str]:
        """Return headers dict with auth for HttpClient."""
        state = self._get_or_raise(session_name)
        self._context.touch_session(self._hunt_id, session_name)
        return dict(state.headers)

    def apply_to_cookies(self, session_name: str) -> dict[str, str]:
        """Return cookies dict for HttpClient."""
        state = self._get_or_raise(session_name)
        self._context.touch_session(self._hunt_id, session_name)
        return dict(state.cookies)

    def get(self, session_name: str) -> SessionState | None:
        """Get a session by name, or None if not found.

        Returns a deep copy so callers cannot accidentally mutate cached state.
        Internal methods use _get_or_raise which returns the cached reference.
        """
        if session_name in self._cache:
            return copy.deepcopy(self._cache[session_name])
        state = self._load(session_name)
        return copy.deepcopy(state) if state else None

    def list_sessions(self) -> list[SessionState]:
        """List all sessions for this hunt."""
        rows = self._context.get_sessions(self._hunt_id)
        result = []
        for r in rows:
            state = self._row_to_state(r)
            self._cache[state.name] = state
            result.append(state)
        return result

    def delete(self, session_name: str) -> None:
        """Delete a session."""
        self._context.delete_session(self._hunt_id, session_name)
        self._cache.pop(session_name, None)

    def invalidate(self, session_name: str) -> None:
        """Mark a session as invalid (e.g., expired token)."""
        state = self._get_or_raise(session_name)
        state.is_valid = False
        self._persist(state)

    # ── Internal ──

    def _get_or_raise(self, session_name: str) -> SessionState:
        state = self.get(session_name)
        if state is None:
            raise SessionError(f"Session '{session_name}' not found")
        return state

    def _persist(self, state: SessionState) -> None:
        self._context.upsert_session(
            self._hunt_id,
            {
                "name": state.name,
                "target_url": state.target_url,
                "auth_method": state.auth_method.value,
                "cookies": state.cookies,
                "headers": state.headers,
                "tokens": state.tokens,
                "storage_state": state.storage_state,
                "is_valid": state.is_valid,
            },
        )
        self._cache[state.name] = state

    def _load(self, session_name: str) -> SessionState | None:
        row = self._context.get_session(self._hunt_id, session_name)
        if not row:
            return None
        state = self._row_to_state(row)
        self._cache[session_name] = state
        return state

    def _row_to_state(self, row: dict[str, Any]) -> SessionState:
        return SessionState(
            name=row["name"],
            target_url=row["target_url"],
            auth_method=AuthMethod(row.get("auth_method", "form")),
            cookies=row.get("cookies", {}),
            headers=row.get("headers", {}),
            tokens=row.get("tokens", {}),
            storage_state=row.get("storage_state"),
            is_valid=row.get("is_valid", True),
            created_at=row.get("created_at", ""),
            last_used_at=row.get("last_used_at", ""),
        )
