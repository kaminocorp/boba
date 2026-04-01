"""CLI smoke tests using Typer's CliRunner."""

from __future__ import annotations

import json
import re
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from boba.cli.main import app
from boba.core.models import ToolResult

runner = CliRunner()


def _make_result(tool_name: str, records: list[dict]) -> ToolResult:
    """Build a fake ToolResult for mocking tool functions."""
    return ToolResult(
        tool_name=tool_name,
        command=[tool_name],
        exit_code=0,
        raw_stdout="",
        raw_stderr="",
        duration_seconds=1.0,
        records=records,
        filtered_count=0,
    )


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


class TestHuntCreateJsonScopeRules:
    """Fix 5: JSON output from hunt_create now includes scope_rules count."""

    def test_hunt_create_json_includes_scope_rules(self, tmp_path):
        result = runner.invoke(
            app,
            [
                "hunt",
                "create",
                "--name",
                "Scope Rules Hunt",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "scope_rules" in data


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
        result = runner.invoke(app, ["context", "subdomains", hunt_id, "--data-dir", str(tmp_path)])
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

        result = runner.invoke(app, ["context", "subdomains", hunt_id, "--data-dir", str(tmp_path)])
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
        result = runner.invoke(app, ["context", "findings", hunt_id, "--data-dir", str(tmp_path)])
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

        result = runner.invoke(app, ["context", "findings", hunt_id, "--data-dir", str(tmp_path)])
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
        result = runner.invoke(app, ["context", "sessions", hunt_id, "--data-dir", str(tmp_path)])
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

        result = runner.invoke(app, ["context", "sessions", hunt_id, "--data-dir", str(tmp_path)])
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


# ═══════════════════ RECON CLI TESTS ═══════════════════


class TestReconSubdomainsCLI:
    def test_recon_subdomains(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        records = [{"subdomain": "api.example.com", "source": "subfinder"}]
        mock_fn = AsyncMock(return_value=_make_result("subfinder", records))
        with patch("boba.tools.recon.subdomains", mock_fn):
            result = runner.invoke(
                app,
                [
                    "recon",
                    "subdomains",
                    hunt_id,
                    "--domain",
                    "example.com",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0
        assert "api.example.com" in result.output

    def test_recon_subdomains_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        records = [{"subdomain": "web.example.com", "source": "subfinder"}]
        mock_fn = AsyncMock(return_value=_make_result("subfinder", records))
        with patch("boba.tools.recon.subdomains", mock_fn):
            result = runner.invoke(
                app,
                [
                    "recon",
                    "subdomains",
                    hunt_id,
                    "--domain",
                    "example.com",
                    "--format",
                    "json",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["found"] == 1


class TestReconHostsCLI:
    def test_recon_hosts_with_targets(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        records = [{"host": "api.example.com", "status_code": 200, "source": "httpx"}]
        mock_fn = AsyncMock(return_value=_make_result("httpx", records))
        with patch("boba.tools.recon.hosts", mock_fn):
            result = runner.invoke(
                app,
                [
                    "recon",
                    "hosts",
                    hunt_id,
                    "--targets",
                    "api.example.com,web.example.com",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0
        # Verify comma-split targets were passed correctly
        call_args = mock_fn.call_args
        targets_arg = call_args[1].get("targets") or call_args[0][2]
        assert targets_arg == ["api.example.com", "web.example.com"]

    def test_recon_hosts_no_targets(self, tmp_path):
        """When --targets is omitted, None is passed to the tool (pulls from context)."""
        hunt_id = _create_hunt(tmp_path)
        mock_fn = AsyncMock(return_value=_make_result("httpx", []))
        with patch("boba.tools.recon.hosts", mock_fn):
            result = runner.invoke(
                app,
                ["recon", "hosts", hunt_id, "--data-dir", str(tmp_path)],
            )
        assert result.exit_code == 0
        call_args = mock_fn.call_args
        targets_arg = call_args[1].get("targets") or call_args[0][2]
        assert targets_arg is None


class TestReconPortsCLI:
    def test_recon_ports_with_targets(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        records = [{"host": "api.example.com", "port": 443, "protocol": "tcp"}]
        mock_fn = AsyncMock(return_value=_make_result("naabu", records))
        with patch("boba.tools.recon.ports", mock_fn):
            result = runner.invoke(
                app,
                [
                    "recon",
                    "ports",
                    hunt_id,
                    "--targets",
                    "api.example.com",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0

    def test_recon_ports_no_targets(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_fn = AsyncMock(return_value=_make_result("naabu", []))
        with patch("boba.tools.recon.ports", mock_fn):
            result = runner.invoke(
                app,
                ["recon", "ports", hunt_id, "--data-dir", str(tmp_path)],
            )
        assert result.exit_code == 0
        call_args = mock_fn.call_args
        targets_arg = call_args[1].get("targets") or call_args[0][2]
        assert targets_arg is None


class TestReconUrlsCLI:
    def test_recon_urls(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        records = [{"url": "https://example.com/login", "source": "gau"}]
        mock_fn = AsyncMock(return_value=_make_result("recon.urls", records))
        with patch("boba.tools.recon.urls", mock_fn):
            result = runner.invoke(
                app,
                [
                    "recon",
                    "urls",
                    hunt_id,
                    "--domain",
                    "example.com",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0


class TestReconTechCLI:
    def test_recon_tech_with_targets(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        records = [{"host": "example.com", "technologies": [{"name": "nginx", "version": "1.19"}]}]
        mock_fn = AsyncMock(return_value=_make_result("whatweb", records))
        with patch("boba.tools.recon.tech", mock_fn):
            result = runner.invoke(
                app,
                [
                    "recon",
                    "tech",
                    hunt_id,
                    "--targets",
                    "https://example.com",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0
        assert "nginx" in result.output

    def test_recon_tech_no_targets(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_fn = AsyncMock(return_value=_make_result("whatweb", []))
        with patch("boba.tools.recon.tech", mock_fn):
            result = runner.invoke(
                app,
                ["recon", "tech", hunt_id, "--data-dir", str(tmp_path)],
            )
        assert result.exit_code == 0


# ═══════════════════ ENUM CLI TESTS ═══════════════════


class TestEnumDirectoriesCLI:
    def test_enum_directories(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        records = [{"url": "https://example.com/admin", "status_code": 200, "content_length": 500}]
        mock_fn = AsyncMock(return_value=_make_result("ffuf", records))
        with patch("boba.tools.enum.directories", mock_fn):
            result = runner.invoke(
                app,
                [
                    "enum",
                    "directories",
                    hunt_id,
                    "--url",
                    "https://example.com/FUZZ",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0

    def test_enum_directories_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        records = [{"url": "https://example.com/secret", "status_code": 403}]
        mock_fn = AsyncMock(return_value=_make_result("ffuf", records))
        with patch("boba.tools.enum.directories", mock_fn):
            result = runner.invoke(
                app,
                [
                    "enum",
                    "directories",
                    hunt_id,
                    "--url",
                    "https://example.com/FUZZ",
                    "--format",
                    "json",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["found"] == 1


# ═══════════════════ SCAN CLI TESTS ═══════════════════


class TestScanNucleiCLI:
    def test_scan_nuclei_with_targets(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        records = [
            {
                "template_id": "cve-2021-1234",
                "severity": "high",
                "url": "https://example.com",
                "template_name": "Test CVE",
            }
        ]
        mock_fn = AsyncMock(return_value=_make_result("nuclei", records))
        with patch("boba.tools.scan.nuclei_scan", mock_fn):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "nuclei",
                    hunt_id,
                    "--targets",
                    "https://example.com",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0

    def test_scan_nuclei_no_targets(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_fn = AsyncMock(return_value=_make_result("nuclei", []))
        with patch("boba.tools.scan.nuclei_scan", mock_fn):
            result = runner.invoke(
                app,
                ["scan", "nuclei", hunt_id, "--data-dir", str(tmp_path)],
            )
        assert result.exit_code == 0
        call_args = mock_fn.call_args
        targets_arg = call_args[1].get("targets") or call_args[0][2]
        assert targets_arg is None

    def test_scan_nuclei_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        records = [{"template_id": "exposed-env", "severity": "medium", "url": "https://e.com"}]
        mock_fn = AsyncMock(return_value=_make_result("nuclei", records))
        with patch("boba.tools.scan.nuclei_scan", mock_fn):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "nuclei",
                    hunt_id,
                    "--targets",
                    "https://e.com",
                    "--format",
                    "json",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["found"] == 1


# ═══════════════════ SESSION CLI TESTS ═══════════════════


class TestSessionCreateCLI:
    def test_session_create(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            [
                "session",
                "create",
                hunt_id,
                "--name",
                "attacker",
                "--target",
                "https://example.com",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        assert "attacker" in result.output

    def test_session_create_invalid_method(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            [
                "session",
                "create",
                hunt_id,
                "--name",
                "test",
                "--target",
                "https://example.com",
                "--method",
                "invalid_method",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 1

    def test_session_create_json(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            [
                "session",
                "create",
                hunt_id,
                "--name",
                "owner",
                "--target",
                "https://example.com",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "owner"


class TestSessionListCLI:
    def test_session_list_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(app, ["session", "list", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0

    def test_session_list_after_create(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        runner.invoke(
            app,
            [
                "session",
                "create",
                hunt_id,
                "--name",
                "my-session",
                "--target",
                "https://example.com",
                "--data-dir",
                str(tmp_path),
            ],
        )
        result = runner.invoke(app, ["session", "list", hunt_id, "--data-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "my-session" in result.output


class TestSessionDeleteCLI:
    def test_session_delete(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        runner.invoke(
            app,
            [
                "session",
                "create",
                hunt_id,
                "--name",
                "to-delete",
                "--target",
                "https://example.com",
                "--data-dir",
                str(tmp_path),
            ],
        )
        result = runner.invoke(
            app, ["session", "delete", hunt_id, "to-delete", "--data-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "deleted" in result.output.lower()


# ═══════════════════ HTTP HEADER VALIDATION ═══════════════════


class TestHttpHeaderValidation:
    def test_invalid_header_format(self, tmp_path):
        """Headers without colon should produce an error, not be silently caught."""
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            [
                "http",
                "request",
                hunt_id,
                "--url",
                "https://example.com",
                "--header",
                "BadHeader",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 1
        assert "KEY:VALUE" in result.output
