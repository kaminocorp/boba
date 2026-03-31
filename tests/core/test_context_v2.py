"""Tests for V2 context additions: http_history, sessions, findings, oob_listeners."""

from __future__ import annotations

import json

import pytest

from boba.core.context import HuntContext
from boba.core.models import Hunt, ScopeConfig


@pytest.fixture
def hunt_id(context):
    """Create a hunt and return its ID."""
    hunt = Hunt(id="test123456ab", name="V2 Test Hunt", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


# ═══════════════════ HTTP HISTORY ═══════════════════


class TestHttpHistory:
    def test_insert_and_get(self, context, hunt_id):
        record_id = context.insert_http_record(hunt_id, {
            "method": "GET",
            "url": "https://example.com/api/users",
            "host": "example.com",
            "path": "/api/users",
            "source": "http_client",
            "status_code": 200,
            "request_headers": {"Accept": "application/json"},
            "response_headers": {"Content-Type": "application/json"},
            "response_body": '{"users": []}',
            "response_length": 14,
            "elapsed_ms": 42.5,
        })
        assert record_id > 0

        record = context.get_http_record(record_id)
        assert record is not None
        assert record["method"] == "GET"
        assert record["url"] == "https://example.com/api/users"
        assert record["host"] == "example.com"
        assert record["status_code"] == 200
        assert record["request_headers"] == {"Accept": "application/json"}
        assert record["response_headers"] == {"Content-Type": "application/json"}
        assert record["elapsed_ms"] == 42.5
        assert record["source"] == "http_client"

    def test_query_by_host(self, context, hunt_id):
        for host in ["example.com", "example.com", "other.com"]:
            context.insert_http_record(hunt_id, {
                "method": "GET",
                "url": f"https://{host}/",
                "host": host,
                "source": "browser",
            })
        results = context.query_http_history(hunt_id, host="example.com")
        assert len(results) == 2

    def test_query_by_method_and_status(self, context, hunt_id):
        context.insert_http_record(hunt_id, {
            "method": "POST", "url": "https://x.com/api", "host": "x.com",
            "source": "http_client", "status_code": 201,
        })
        context.insert_http_record(hunt_id, {
            "method": "GET", "url": "https://x.com/api", "host": "x.com",
            "source": "http_client", "status_code": 200,
        })
        results = context.query_http_history(hunt_id, method="POST")
        assert len(results) == 1
        assert results[0]["status_code"] == 201

    def test_query_limit(self, context, hunt_id):
        for i in range(10):
            context.insert_http_record(hunt_id, {
                "method": "GET", "url": f"https://x.com/{i}", "host": "x.com",
                "source": "browser",
            })
        results = context.query_http_history(hunt_id, limit=3)
        assert len(results) == 3

    def test_tags_and_notes(self, context, hunt_id):
        rid = context.insert_http_record(hunt_id, {
            "method": "GET", "url": "https://x.com/", "host": "x.com",
            "source": "manual",
        })
        context.update_http_record_tags(rid, ["interesting", "auth"])
        context.update_http_record_tags(rid, ["auth", "idor-evidence"])

        record = context.get_http_record(rid)
        assert set(record["tags"]) == {"interesting", "auth", "idor-evidence"}

        context.update_http_record_notes(rid, "Potential IDOR on user endpoint")
        record = context.get_http_record(rid)
        assert record["notes"] == "Potential IDOR on user endpoint"

    def test_parent_request_id(self, context, hunt_id):
        parent = context.insert_http_record(hunt_id, {
            "method": "GET", "url": "https://x.com/original", "host": "x.com",
            "source": "http_client",
        })
        child = context.insert_http_record(hunt_id, {
            "method": "GET", "url": "https://x.com/original", "host": "x.com",
            "source": "replay", "parent_request_id": parent,
        })
        record = context.get_http_record(child)
        assert record["parent_request_id"] == parent


# ═══════════════════ SESSIONS ═══════════════════


class TestSessions:
    def test_create_and_get(self, context, hunt_id):
        context.upsert_session(hunt_id, {
            "name": "user_a",
            "target_url": "https://app.example.com",
            "auth_method": "bearer",
            "cookies": {"session": "abc123"},
            "headers": {"Authorization": "Bearer tok123"},
            "tokens": {"access_token": "tok123"},
        })
        session = context.get_session(hunt_id, "user_a")
        assert session is not None
        assert session["name"] == "user_a"
        assert session["target_url"] == "https://app.example.com"
        assert session["auth_method"] == "bearer"
        assert session["cookies"] == {"session": "abc123"}
        assert session["headers"] == {"Authorization": "Bearer tok123"}
        assert session["tokens"] == {"access_token": "tok123"}
        assert session["is_valid"] is True

    def test_upsert_updates_existing(self, context, hunt_id):
        context.upsert_session(hunt_id, {
            "name": "user_a",
            "target_url": "https://app.example.com",
            "cookies": {"session": "old"},
        })
        context.upsert_session(hunt_id, {
            "name": "user_a",
            "target_url": "https://app.example.com",
            "cookies": {"session": "new"},
        })
        sessions = context.get_sessions(hunt_id)
        assert len(sessions) == 1
        assert sessions[0]["cookies"] == {"session": "new"}

    def test_list_sessions(self, context, hunt_id):
        for name in ["user_a", "user_b", "admin"]:
            context.upsert_session(hunt_id, {
                "name": name, "target_url": "https://app.example.com",
            })
        sessions = context.get_sessions(hunt_id)
        assert len(sessions) == 3
        assert [s["name"] for s in sessions] == ["admin", "user_a", "user_b"]

    def test_delete_session(self, context, hunt_id):
        context.upsert_session(hunt_id, {
            "name": "tmp", "target_url": "https://app.example.com",
        })
        context.delete_session(hunt_id, "tmp")
        assert context.get_session(hunt_id, "tmp") is None

    def test_touch_session(self, context, hunt_id):
        context.upsert_session(hunt_id, {
            "name": "user_a", "target_url": "https://app.example.com",
        })
        s1 = context.get_session(hunt_id, "user_a")
        context.touch_session(hunt_id, "user_a")
        s2 = context.get_session(hunt_id, "user_a")
        # last_used_at should be updated (or same if instant)
        assert s2["last_used_at"] >= s1["last_used_at"]


# ═══════════════════ FINDINGS ═══════════════════


class TestFindings:
    def test_upsert_and_query(self, context, hunt_id):
        fid = context.upsert_finding(hunt_id, {
            "finding_type": "idor",
            "severity": "high",
            "title": "IDOR on /api/users/{id}",
            "description": "User B can access User A data",
            "url": "https://app.example.com/api/users/123",
            "parameter": "id",
            "evidence": [{"note": "response bodies match"}],
            "request_ids": [1, 2, 3],
            "confirmed": True,
            "tags": ["idor", "api"],
        })
        assert fid > 0

        findings = context.get_findings(hunt_id)
        assert len(findings) == 1
        f = findings[0]
        assert f["finding_type"] == "idor"
        assert f["severity"] == "high"
        assert f["confirmed"] is True
        assert f["request_ids"] == [1, 2, 3]
        assert f["tags"] == ["idor", "api"]

    def test_query_by_type_and_severity(self, context, hunt_id):
        context.upsert_finding(hunt_id, {
            "finding_type": "xss", "severity": "medium",
            "title": "Reflected XSS", "url": "https://x.com/search",
        })
        context.upsert_finding(hunt_id, {
            "finding_type": "ssrf", "severity": "critical",
            "title": "Blind SSRF", "url": "https://x.com/proxy",
        })
        assert len(context.get_findings(hunt_id, finding_type="xss")) == 1
        assert len(context.get_findings(hunt_id, severity="critical")) == 1
        assert len(context.get_findings(hunt_id, finding_type="sqli")) == 0

    def test_upsert_deduplicates(self, context, hunt_id):
        """Same (hunt_id, finding_type, url, parameter) should update, not duplicate."""
        context.upsert_finding(hunt_id, {
            "finding_type": "idor", "severity": "medium",
            "title": "IDOR v1", "url": "https://x.com/api",
            "parameter": "id",
        })
        context.upsert_finding(hunt_id, {
            "finding_type": "idor", "severity": "high",
            "title": "IDOR v2 — confirmed", "url": "https://x.com/api",
            "parameter": "id", "confirmed": True,
        })
        findings = context.get_findings(hunt_id)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["title"] == "IDOR v2 — confirmed"
        assert findings[0]["confirmed"] is True


# ═══════════════════ OOB LISTENERS ═══════════════════


class TestOOBListeners:
    def test_insert_and_list(self, context, hunt_id):
        lid = context.insert_oob_listener(hunt_id, {
            "listener_id": "abc123",
            "callback_domain": "abc123.oast.fun",
            "purpose": "blind_ssrf",
            "target_url": "https://x.com/proxy",
            "parameter": "url",
        })
        assert lid > 0

        listeners = context.get_oob_listeners(hunt_id)
        assert len(listeners) == 1
        assert listeners[0]["listener_id"] == "abc123"
        assert listeners[0]["callback_domain"] == "abc123.oast.fun"
        assert listeners[0]["purpose"] == "blind_ssrf"

    def test_update_interactions(self, context, hunt_id):
        context.insert_oob_listener(hunt_id, {
            "listener_id": "abc123",
            "callback_domain": "abc123.oast.fun",
        })
        interactions = [
            {"type": "dns", "remote_address": "10.0.0.5", "timestamp": "2026-03-31T12:00:00Z"},
            {"type": "http", "remote_address": "10.0.0.5", "timestamp": "2026-03-31T12:00:01Z"},
        ]
        context.update_oob_interactions(hunt_id, "abc123", interactions)

        listeners = context.get_oob_listeners(hunt_id)
        assert len(listeners[0]["interactions"]) == 2
        assert listeners[0]["interactions"][0]["type"] == "dns"


# ═══════════════════ STATS INCLUDE V2 TABLES ═══════════════════


class TestV2Stats:
    def test_stats_include_new_tables(self, context, hunt_id):
        stats = context.get_hunt_stats(hunt_id)
        assert "http_history" in stats
        assert "sessions" in stats
        assert "findings" in stats
        assert stats["http_history"] == 0
        assert stats["sessions"] == 0
        assert stats["findings"] == 0
