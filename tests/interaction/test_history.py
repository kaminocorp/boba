"""Tests for HttpHistorySink."""

from __future__ import annotations

import pytest

from boba.core.context import HuntContext
from boba.core.models import Hunt, ScopeConfig
from boba.interaction.history import BODY_INLINE_LIMIT, HttpHistorySink


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="sink_test_001", name="Sink Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


@pytest.fixture
def sink(context, hunt_id, tmp_path, monkeypatch):
    """HttpHistorySink backed by temp DB, with body dir redirected to tmp_path."""
    s = HttpHistorySink(context, hunt_id)
    # Override body dir to use tmp_path
    s._body_dir = tmp_path / "bodies"
    s._body_dir.mkdir()
    return s


class TestRecord:
    def test_basic_record(self, sink):
        rid = sink.record(
            method="GET",
            url="https://example.com/api/users",
            request_headers={"Accept": "application/json"},
            request_body=None,
            status_code=200,
            response_headers={"Content-Type": "application/json"},
            response_body=b'{"users": []}',
            elapsed_ms=42.5,
            source="http_client",
        )
        assert rid > 0

        record = sink.get(rid)
        assert record is not None
        assert record["method"] == "GET"
        assert record["host"] == "example.com"
        assert record["path"] == "/api/users"
        assert record["status_code"] == 200
        assert record["source"] == "http_client"

    def test_record_with_session(self, sink):
        rid = sink.record(
            method="GET",
            url="https://app.example.com/dashboard",
            request_headers={},
            request_body=None,
            status_code=200,
            response_headers={},
            response_body=b"<html>...</html>",
            elapsed_ms=100.0,
            source="browser",
            session_name="user_a",
        )
        record = sink.get(rid)
        assert record["session_name"] == "user_a"

    def test_record_with_tags(self, sink):
        rid = sink.record(
            method="POST",
            url="https://app.example.com/login",
            request_headers={},
            request_body=b"user=admin&pass=secret",
            status_code=302,
            response_headers={"location": "/dashboard"},
            response_body=None,
            elapsed_ms=50.0,
            tags=["auth", "login"],
        )
        record = sink.get(rid)
        assert set(record["tags"]) == {"auth", "login"}
        assert record["is_redirect"] == 1

    def test_redirect_detection(self, sink):
        for code in [301, 302, 303, 307, 308]:
            rid = sink.record(
                method="GET", url=f"https://x.com/{code}",
                request_headers={}, request_body=None,
                status_code=code,
                response_headers={"location": "/dest"},
                response_body=None, elapsed_ms=10.0,
            )
            record = sink.get(rid)
            assert record["is_redirect"] == 1, f"Expected redirect for {code}"

    def test_parent_request_id(self, sink):
        parent = sink.record(
            method="GET", url="https://x.com/original",
            request_headers={}, request_body=None,
            status_code=200, response_headers={},
            response_body=b"ok", elapsed_ms=10.0,
            source="http_client",
        )
        child = sink.record(
            method="GET", url="https://x.com/original",
            request_headers={"X-Modified": "true"}, request_body=None,
            status_code=200, response_headers={},
            response_body=b"ok", elapsed_ms=15.0,
            source="replay", parent_request_id=parent,
        )
        record = sink.get(child)
        assert record["parent_request_id"] == parent


class TestLargeBodyStorage:
    def test_small_body_stored_inline(self, sink):
        body = b"small body"
        rid = sink.record(
            method="GET", url="https://x.com/small",
            request_headers={}, request_body=None,
            status_code=200, response_headers={},
            response_body=body, elapsed_ms=10.0,
        )
        record = sink.get(rid)
        assert record["response_body"] == "small body"
        assert record["response_body_ref"] is None

    def test_large_body_stored_as_file(self, sink):
        body = b"x" * (BODY_INLINE_LIMIT + 1000)
        rid = sink.record(
            method="GET", url="https://x.com/large",
            request_headers={}, request_body=None,
            status_code=200, response_headers={},
            response_body=body, elapsed_ms=10.0,
        )
        record = sink.get(rid)
        # Inline should be a truncated preview
        assert record["response_body_ref"] is not None
        assert len(record["response_body"]) < len(body)

        # Full body should be retrievable from file
        full = sink.get_full_body(rid, which="response")
        assert full == body

    def test_large_request_body_stored_as_file(self, sink):
        body = b"y" * (BODY_INLINE_LIMIT + 500)
        rid = sink.record(
            method="POST", url="https://x.com/upload",
            request_headers={}, request_body=body,
            status_code=201, response_headers={},
            response_body=b"ok", elapsed_ms=20.0,
        )
        record = sink.get(rid)
        assert record["request_body_ref"] is not None

        full = sink.get_full_body(rid, which="request")
        assert full == body


class TestQuery:
    def test_query_by_host(self, sink):
        sink.record(
            method="GET", url="https://a.com/", request_headers={},
            request_body=None, status_code=200, response_headers={},
            response_body=b"ok", elapsed_ms=10.0,
        )
        sink.record(
            method="GET", url="https://b.com/", request_headers={},
            request_body=None, status_code=200, response_headers={},
            response_body=b"ok", elapsed_ms=10.0,
        )
        results = sink.query(host="a.com")
        assert len(results) == 1
        assert results[0]["host"] == "a.com"

    def test_query_by_source(self, sink):
        sink.record(
            method="GET", url="https://x.com/1", request_headers={},
            request_body=None, status_code=200, response_headers={},
            response_body=b"ok", elapsed_ms=10.0, source="browser",
        )
        sink.record(
            method="GET", url="https://x.com/2", request_headers={},
            request_body=None, status_code=200, response_headers={},
            response_body=b"ok", elapsed_ms=10.0, source="http_client",
        )
        results = sink.query(source="browser")
        assert len(results) == 1


class TestAnnotation:
    def test_tag_and_annotate(self, sink):
        rid = sink.record(
            method="GET", url="https://x.com/", request_headers={},
            request_body=None, status_code=200, response_headers={},
            response_body=b"ok", elapsed_ms=10.0,
        )
        sink.tag(rid, ["interesting", "idor"])
        sink.annotate(rid, "Check this endpoint with other user")

        record = sink.get(rid)
        assert "interesting" in record["tags"]
        assert "idor" in record["tags"]
        assert record["notes"] == "Check this endpoint with other user"
