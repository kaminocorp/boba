"""Tests for SessionManager."""

from __future__ import annotations

import pytest

from boba.core.errors import SessionError
from boba.core.models import AuthMethod, Hunt, ScopeConfig
from boba.interaction.session import SessionManager


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="sess_test_001", name="Session Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


@pytest.fixture
def mgr(context, hunt_id):
    return SessionManager(context, hunt_id)


class TestCreateAndGet:
    def test_create_session(self, mgr):
        state = mgr.create("user_a", "https://app.example.com")
        assert state.name == "user_a"
        assert state.target_url == "https://app.example.com"
        assert state.auth_method == AuthMethod.FORM
        assert state.is_valid is True

    def test_get_session(self, mgr):
        mgr.create("user_a", "https://app.example.com")
        state = mgr.get("user_a")
        assert state is not None
        assert state.name == "user_a"

    def test_get_nonexistent_returns_none(self, mgr):
        assert mgr.get("nope") is None


class TestLogin:
    def test_login_bearer(self, mgr):
        mgr.create("api_user", "https://api.example.com")
        state = mgr.login_bearer("api_user", "tok_abc123")
        assert state.auth_method == AuthMethod.BEARER
        assert state.headers["Authorization"] == "Bearer tok_abc123"
        assert state.tokens["access_token"] == "tok_abc123"

    def test_login_basic(self, mgr):
        mgr.create("basic_user", "https://app.example.com")
        state = mgr.login_basic("basic_user", "admin", "password")
        assert state.auth_method == AuthMethod.BASIC
        assert state.headers["Authorization"].startswith("Basic ")

    def test_login_cookies(self, mgr):
        mgr.create("cookie_user", "https://app.example.com")
        state = mgr.login_cookies("cookie_user", {"session": "abc", "csrf": "xyz"})
        assert state.auth_method == AuthMethod.COOKIE
        assert state.cookies == {"session": "abc", "csrf": "xyz"}

    def test_login_custom_header(self, mgr):
        mgr.create("api_key_user", "https://api.example.com")
        state = mgr.login_header("api_key_user", "X-API-Key", "secret_key_123")
        assert state.auth_method == AuthMethod.CUSTOM_HEADER
        assert state.headers["X-API-Key"] == "secret_key_123"

    def test_login_nonexistent_raises(self, mgr):
        with pytest.raises(SessionError, match="not found"):
            mgr.login_bearer("nope", "token")


class TestApply:
    def test_apply_to_headers(self, mgr):
        mgr.create("user_a", "https://app.example.com")
        mgr.login_bearer("user_a", "tok_abc")
        headers = mgr.apply_to_headers("user_a")
        assert headers["Authorization"] == "Bearer tok_abc"

    def test_apply_to_cookies(self, mgr):
        mgr.create("user_a", "https://app.example.com")
        mgr.login_cookies("user_a", {"session": "abc"})
        cookies = mgr.apply_to_cookies("user_a")
        assert cookies["session"] == "abc"


class TestListAndDelete:
    def test_list_sessions(self, mgr):
        mgr.create("user_a", "https://app.example.com")
        mgr.create("user_b", "https://app.example.com")
        sessions = mgr.list_sessions()
        assert len(sessions) == 2
        names = {s.name for s in sessions}
        assert names == {"user_a", "user_b"}

    def test_delete_session(self, mgr):
        mgr.create("tmp", "https://app.example.com")
        mgr.delete("tmp")
        assert mgr.get("tmp") is None

    def test_invalidate_session(self, mgr):
        mgr.create("user_a", "https://app.example.com")
        mgr.invalidate("user_a")
        state = mgr.get("user_a")
        assert state.is_valid is False


class TestCreateDeepCopy:
    """create() must return a deep copy so callers cannot mutate the cache."""

    def test_create_returns_deep_copy(self, mgr):
        state = mgr.create("user_a", "https://app.example.com")
        # Mutate the returned object
        state.cookies["injected"] = "evil"
        state.headers["X-Evil"] = "yes"
        # Cache must be unaffected
        fresh = mgr.get("user_a")
        assert "injected" not in fresh.cookies
        assert "X-Evil" not in fresh.headers


class TestListSessionsDeepCopy:
    """list_sessions() must return deep copies, same as get()."""

    def test_list_returns_deep_copies(self, mgr):
        mgr.create("user_a", "https://app.example.com")
        sessions = mgr.list_sessions()
        # Mutate the returned object
        sessions[0].cookies["injected"] = "evil"
        # Original cache must be unaffected
        fresh = mgr.get("user_a")
        assert "injected" not in fresh.cookies


class TestLoginDeepCopy:
    """Fix 2: login_* methods must return deep copies so callers cannot mutate the cache."""

    def test_login_bearer_returns_deep_copy(self, mgr):
        mgr.create("api_user", "https://api.example.com")
        state = mgr.login_bearer("api_user", "tok_abc123")
        # Mutate the returned object
        state.headers["X-Evil"] = "injected"
        state.tokens["backdoor"] = "yes"
        # Cache must be unaffected
        fresh = mgr.get("api_user")
        assert "X-Evil" not in fresh.headers
        assert "backdoor" not in fresh.tokens

    def test_login_basic_returns_deep_copy(self, mgr):
        mgr.create("basic_user", "https://app.example.com")
        state = mgr.login_basic("basic_user", "admin", "password")
        state.headers["X-Evil"] = "injected"
        fresh = mgr.get("basic_user")
        assert "X-Evil" not in fresh.headers

    def test_login_cookies_returns_deep_copy(self, mgr):
        mgr.create("cookie_user", "https://app.example.com")
        state = mgr.login_cookies("cookie_user", {"session": "abc"})
        state.cookies["injected"] = "evil"
        fresh = mgr.get("cookie_user")
        assert "injected" not in fresh.cookies

    def test_login_header_returns_deep_copy(self, mgr):
        mgr.create("header_user", "https://api.example.com")
        state = mgr.login_header("header_user", "X-API-Key", "secret")
        state.headers["X-Evil"] = "injected"
        fresh = mgr.get("header_user")
        assert "X-Evil" not in fresh.headers


class TestPersistence:
    def test_session_survives_new_manager(self, context, hunt_id):
        """Session created by one manager instance can be read by another."""
        mgr1 = SessionManager(context, hunt_id)
        mgr1.create("persistent", "https://app.example.com")
        mgr1.login_bearer("persistent", "tok_xyz")

        # New manager instance, same context
        mgr2 = SessionManager(context, hunt_id)
        state = mgr2.get("persistent")
        assert state is not None
        assert state.headers["Authorization"] == "Bearer tok_xyz"
