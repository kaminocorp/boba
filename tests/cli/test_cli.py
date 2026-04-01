"""CLI smoke tests using Typer's CliRunner."""

from __future__ import annotations

import json
import re

from typer.testing import CliRunner

from boba.cli.main import app

runner = CliRunner()


def _create_hunt(tmp_path: str, name: str = "Test Hunt") -> str:
    """Helper: create a hunt and return its ID."""
    result = runner.invoke(app, ["hunt", "create", "--name", name, "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, f"hunt create failed: {result.output}"
    # Extract hunt ID from output like "Hunt created: <uuid>"
    match = re.search(r"Hunt created: (\S+)", result.output)
    assert match, f"Could not find hunt ID in output: {result.output}"
    return match.group(1)


class TestHuntCreate:
    def test_hunt_create(self, tmp_path):
        result = runner.invoke(
            app, ["hunt", "create", "--name", "Test Hunt", "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "Hunt created:" in result.output

    def test_hunt_create_json_format(self, tmp_path):
        result = runner.invoke(
            app,
            [
                "hunt",
                "create",
                "--name",
                "JSON Hunt",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "id" in data
        assert data["name"] == "JSON Hunt"
        assert data["status"] == "active"


class TestHuntList:
    def test_hunt_list_empty(self, tmp_path):
        result = runner.invoke(app, ["hunt", "list", "--data-dir", str(tmp_path)])
        assert result.exit_code == 0

    def test_hunt_list_after_create(self, tmp_path):
        _create_hunt(tmp_path, "Listed Hunt")
        result = runner.invoke(app, ["hunt", "list", "--data-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "Listed Hunt" in result.output


class TestHuntStatus:
    def test_hunt_status(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(app, ["hunt", "status", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert hunt_id in result.output or "Test Hunt" in result.output


class TestHuntPause:
    def test_hunt_pause(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(app, ["hunt", "pause", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "paused" in result.output.lower()


class TestHuntClose:
    def test_hunt_close(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(app, ["hunt", "close", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "closed" in result.output.lower()


class TestInvalidFormat:
    def test_invalid_format(self, tmp_path):
        result = runner.invoke(
            app,
            ["hunt", "list", "--format", "xml", "--data-dir", str(tmp_path)],
        )
        # format_output raises typer.Exit(1) for invalid format
        assert result.exit_code == 1


class TestContextStats:
    def test_context_stats(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(app, ["context", "stats", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0


class TestHuntResume:
    def test_pause_then_resume(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        # Pause first
        result = runner.invoke(app, ["hunt", "pause", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "paused" in result.output.lower()
        # Resume
        result = runner.invoke(app, ["hunt", "resume", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "resumed" in result.output.lower()
        # Verify status is active again
        result = runner.invoke(
            app, ["hunt", "status", hunt_id, "--format", "json", "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "active"


def _insert_manager(tmp_path):
    """Helper: return a HuntManager pointing at the CLI-created DB."""
    from boba.core.hunt import HuntManager

    return HuntManager(db_path=str(tmp_path / "boba.db"))


class TestContextSubdomains:
    def test_subdomains_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app, ["context", "subdomains", hunt_id, "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0

    def test_subdomains_with_data(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_records(
            hunt_id,
            "subdomain",
            [
                {"subdomain": "api.example.com", "source": "test"},
                {"subdomain": "web.example.com", "source": "test"},
            ],
        )
        mgr.close_context()

        result = runner.invoke(
            app, ["context", "subdomains", hunt_id, "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "api.example.com" in result.output
        assert "web.example.com" in result.output

    def test_subdomains_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_records(
            hunt_id,
            "subdomain",
            [{"subdomain": "json.example.com", "source": "test"}],
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            ["context", "subdomains", hunt_id, "--format", "json", "--data-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert any(r["subdomain"] == "json.example.com" for r in data)


class TestContextHosts:
    def test_hosts_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(app, ["context", "hosts", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0

    def test_hosts_with_data(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_records(
            hunt_id,
            "host",
            [{"host": "api.example.com", "ip": "1.2.3.4", "status_code": 200, "source": "test"}],
        )
        mgr.close_context()

        result = runner.invoke(app, ["context", "hosts", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "api.example.com" in result.output

    def test_hosts_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_records(
            hunt_id,
            "host",
            [{"host": "web.example.com", "ip": "5.6.7.8", "status_code": 200, "source": "test"}],
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            ["context", "hosts", hunt_id, "--format", "json", "--data-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert any(r["host"] == "web.example.com" for r in data)


class TestContextPorts:
    def test_ports_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(app, ["context", "ports", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0

    def test_ports_with_data(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_records(
            hunt_id,
            "port",
            [{"host": "api.example.com", "port": 443, "protocol": "tcp", "source": "test"}],
        )
        mgr.close_context()

        result = runner.invoke(app, ["context", "ports", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "443" in result.output

    def test_ports_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_records(
            hunt_id,
            "port",
            [{"host": "api.example.com", "port": 8080, "protocol": "tcp", "source": "test"}],
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            ["context", "ports", hunt_id, "--format", "json", "--data-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert any(r["port"] == 8080 for r in data)


class TestContextUrls:
    def test_urls_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(app, ["context", "urls", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0

    def test_urls_with_data(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_records(
            hunt_id,
            "url",
            [{"url": "https://api.example.com/v1/users", "source": "test"}],
        )
        mgr.close_context()

        result = runner.invoke(app, ["context", "urls", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "api.example.com" in result.output

    def test_urls_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_records(
            hunt_id,
            "url",
            [{"url": "https://web.example.com/login", "source": "test"}],
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            ["context", "urls", hunt_id, "--format", "json", "--data-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 1


class TestContextDirectories:
    def test_directories_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app, ["context", "directories", hunt_id, "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0

    def test_directories_with_data(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_records(
            hunt_id,
            "directory",
            [
                {
                    "url": "https://api.example.com/admin",
                    "status_code": 200,
                    "content_length": 1234,
                    "content_type": "text/html",
                    "source": "test",
                }
            ],
        )
        mgr.close_context()

        result = runner.invoke(
            app, ["context", "directories", hunt_id, "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "admin" in result.output

    def test_directories_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_records(
            hunt_id,
            "directory",
            [
                {
                    "url": "https://api.example.com/secret",
                    "status_code": 403,
                    "content_length": 100,
                    "content_type": "text/html",
                    "source": "test",
                }
            ],
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            ["context", "directories", hunt_id, "--format", "json", "--data-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert any(r["status_code"] == 403 for r in data)


class TestContextRuns:
    def test_runs_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(app, ["context", "runs", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0

    def test_runs_json_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            ["context", "runs", hunt_id, "--format", "json", "--data-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 0


class TestContextHttpHistory:
    def test_http_history_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app, ["context", "http-history", hunt_id, "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0

    def test_http_history_json_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            ["context", "http-history", hunt_id, "--format", "json", "--data-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 0


class TestContextFindings:
    def test_findings_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app, ["context", "findings", hunt_id, "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0

    def test_findings_with_data(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_finding(
            hunt_id,
            {
                "finding_type": "xss",
                "severity": "high",
                "title": "Reflected XSS in search",
                "url": "https://api.example.com/search",
                "parameter": "q",
                "confirmed": True,
            },
        )
        mgr.close_context()

        result = runner.invoke(
            app, ["context", "findings", hunt_id, "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "xss" in result.output.lower() or "XSS" in result.output

    def test_findings_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_finding(
            hunt_id,
            {
                "finding_type": "sqli",
                "severity": "critical",
                "title": "SQL Injection in login",
                "url": "https://api.example.com/login",
                "parameter": "username",
            },
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            ["context", "findings", hunt_id, "--format", "json", "--data-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert any(r["finding_type"] == "sqli" for r in data)


class TestContextSessions:
    def test_sessions_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app, ["context", "sessions", hunt_id, "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0

    def test_sessions_with_data(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_session(
            hunt_id,
            {
                "name": "admin-session",
                "target_url": "https://api.example.com",
                "auth_method": "cookie",
                "cookies": {"session": "abc123"},
                "headers": {},
                "tokens": {},
                "is_valid": True,
            },
        )
        mgr.close_context()

        result = runner.invoke(
            app, ["context", "sessions", hunt_id, "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "admin-session" in result.output

    def test_sessions_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mgr = _insert_manager(tmp_path)
        mgr.context.upsert_session(
            hunt_id,
            {
                "name": "user-session",
                "target_url": "https://api.example.com",
                "auth_method": "bearer",
                "cookies": {},
                "headers": {"Authorization": "Bearer token123"},
                "tokens": {"access_token": "token123"},
                "is_valid": True,
            },
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            ["context", "sessions", hunt_id, "--format", "json", "--data-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert any(r["name"] == "user-session" for r in data)
