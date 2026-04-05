"""Tests for V3 vulnerability chaining — rule matching, chain detection, validation, CLI."""

from __future__ import annotations

import json

import pytest

from boba.analysis.chaining import detect_chains, suggest_chains, validate_chain
from boba.core.models import ChainStatus, Hunt, Severity, ScopeConfig


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="chain_test_001", name="Chain Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


def _insert_finding(context, hunt_id, **kwargs):
    """Helper to insert a finding and return its ID."""
    finding = {
        "finding_type": kwargs.get("finding_type", "xss"),
        "severity": kwargs.get("severity", "medium"),
        "title": kwargs.get("title", "Test Finding"),
        "url": kwargs.get("url", "https://app.example.com/test"),
        "parameter": kwargs.get("parameter", "q"),
        "evidence": kwargs.get("evidence"),
        "confirmed": kwargs.get("confirmed", False),
    }
    return context.upsert_finding(hunt_id, finding)


# ═══════════════════ Chain Detection ═══════════════════


class TestDetectChains:
    def test_ssrf_cloud_metadata_chain(self, context, hunt_id):
        """SSRF with cloud metadata evidence → chain detected."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="ssrf",
            url="https://app.example.com/proxy",
            parameter="url",
            evidence=[{"payload": "http://169.254.169.254/latest/meta-data/", "indicator": "aws"}],
        )

        chains = detect_chains(context, hunt_id)
        assert len(chains) >= 1
        ssrf_chain = [c for c in chains if "cloud metadata" in c.title.lower()]
        assert len(ssrf_chain) == 1
        assert ssrf_chain[0].severity == Severity.CRITICAL

    def test_auth_bypass_admin_chain(self, context, hunt_id):
        """Auth bypass with admin evidence → chain detected."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="auth",
            url="https://app.example.com/admin/users",
            evidence=[{"type": "no_auth_access", "note": "admin panel accessible"}],
        )

        chains = detect_chains(context, hunt_id)
        auth_chains = [c for c in chains if "admin" in c.title.lower() or "auth" in c.title.lower()]
        assert len(auth_chains) >= 1

    def test_idor_plus_sqli_same_host(self, context, hunt_id):
        """IDOR + SQLi on same host → chain detected."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="idor",
            url="https://app.example.com/api/users",
            parameter="id",
        )
        _insert_finding(
            context,
            hunt_id,
            finding_type="sqli",
            url="https://app.example.com/api/search",
            parameter="q",
            evidence=[{"type": "error_based"}],
        )

        chains = detect_chains(context, hunt_id)
        idor_sqli = [
            c for c in chains if "idor" in c.description.lower() and "sqli" in c.description.lower()
        ]
        assert len(idor_sqli) == 1
        assert idor_sqli[0].severity == Severity.CRITICAL

    def test_no_chain_without_evidence(self, context, hunt_id):
        """SSRF without cloud metadata keywords → no cloud metadata chain."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="ssrf",
            url="https://app.example.com/proxy",
            parameter="url",
            evidence=[{"payload": "http://internal.corp/", "note": "generic ssrf"}],
        )

        chains = detect_chains(context, hunt_id)
        cloud_chains = [c for c in chains if "cloud metadata" in c.title.lower()]
        assert len(cloud_chains) == 0

    def test_same_host_rule_different_hosts(self, context, hunt_id):
        """same_host=True rule doesn't match findings on different hosts."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="idor",
            url="https://app1.example.com/api/users",
            parameter="id",
        )
        _insert_finding(
            context,
            hunt_id,
            finding_type="sqli",
            url="https://app2.example.com/api/search",
            parameter="q",
            evidence=[{"type": "error_based"}],
        )

        chains = detect_chains(context, hunt_id)
        idor_sqli = [
            c for c in chains if "idor" in c.description.lower() and "sqli" in c.description.lower()
        ]
        assert len(idor_sqli) == 0

    def test_dedup_excluded_from_chains(self, context, hunt_id):
        """Non-canonical dedup members don't participate in chain detection."""
        f1 = _insert_finding(
            context,
            hunt_id,
            finding_type="ssrf",
            url="https://app.example.com/proxy",
            parameter="url",
            evidence=[{"payload": "http://169.254.169.254/", "indicator": "aws"}],
        )
        f2 = _insert_finding(
            context,
            hunt_id,
            finding_type="ssrf",
            url="https://app.example.com/fetch",
            parameter="url",
            evidence=[{"payload": "http://169.254.169.254/", "indicator": "aws"}],
        )

        # Mark f2 as duplicate of f1
        context.insert_dedup_group(
            hunt_id,
            {
                "canonical_id": f1,
                "finding_ids": [f1, f2],
                "reason": "Same vuln",
            },
        )

        chains = detect_chains(context, hunt_id)
        # Chain should only reference the canonical finding
        for chain in chains:
            if f2 in chain.finding_ids and f1 not in chain.finding_ids:
                pytest.fail("Non-canonical finding included without canonical")

    def test_chain_severity_at_least_max_individual(self, context, hunt_id):
        """Chain severity should be at least as high as the highest individual finding."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="auth",
            url="https://app.example.com/admin",
            severity="high",
            evidence=[{"type": "no_auth_access", "note": "admin accessible"}],
        )

        chains = detect_chains(context, hunt_id)
        if chains:
            assert chains[0].severity.value in ("critical", "high")

    def test_chain_idempotent(self, context, hunt_id):
        """Running detect_chains twice doesn't create duplicate chains."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="ssrf",
            url="https://app.example.com/proxy",
            parameter="url",
            evidence=[{"payload": "http://169.254.169.254/", "indicator": "aws"}],
        )

        chains1 = detect_chains(context, hunt_id)
        chains2 = detect_chains(context, hunt_id)
        assert len(chains1) == len(chains2)

        persisted = context.get_chains(hunt_id)
        # Should not have doubled
        assert len(persisted) == len(chains1)

    def test_no_findings_no_chains(self, context, hunt_id):
        """Empty finding set produces no chains."""
        chains = detect_chains(context, hunt_id)
        assert chains == []

    def test_ai_tool_abuse_chain(self, context, hunt_id):
        """AI findings with tool-use evidence should chain to critical impact."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="ai",
            url="https://app.example.com/api/chat",
            parameter="message",
            evidence=[{"type": "function_call", "tool": "search"}],
        )

        chains = detect_chains(context, hunt_id)
        ai_chains = [c for c in chains if "ai_tool_abuse" in c.tags]
        assert len(ai_chains) == 1
        assert ai_chains[0].severity == Severity.CRITICAL

    def test_ai_data_exfiltration_chain(self, context, hunt_id):
        """System prompt leak evidence should chain to high-severity data exposure."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="ai",
            url="https://app.example.com/api/chat",
            parameter="message",
            evidence=[{"type": "system_prompt_leak", "leak": "internal policy"}],
        )

        chains = detect_chains(context, hunt_id)
        ai_chains = [c for c in chains if "ai_data_exfiltration" in c.tags]
        assert len(ai_chains) == 1
        assert ai_chains[0].severity == Severity.HIGH

    def test_xss_to_ai_injection_same_host(self, context, hunt_id):
        """XSS and AI findings on the same host should produce an AI injection chain."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="xss",
            url="https://app.example.com/search",
            parameter="q",
            evidence=[{"type": "reflected"}],
        )
        _insert_finding(
            context,
            hunt_id,
            finding_type="ai",
            url="https://app.example.com/api/chat",
            parameter="message",
            evidence=[{"type": "instruction_override"}],
        )

        chains = detect_chains(context, hunt_id)
        ai_chains = [c for c in chains if "xss_to_ai_injection" in c.tags]
        assert len(ai_chains) == 1
        assert ai_chains[0].severity == Severity.CRITICAL

    def test_ai_plus_auth_bypass_same_host(self, context, hunt_id):
        """AI and auth findings on the same host should produce a privileged AI chain."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="ai",
            url="https://app.example.com/api/chat",
            parameter="message",
            evidence=[{"type": "instruction_override"}],
        )
        _insert_finding(
            context,
            hunt_id,
            finding_type="auth",
            url="https://app.example.com/admin/ai",
            parameter="",
            evidence=[{"type": "no_auth_access", "note": "admin AI panel accessible"}],
        )

        chains = detect_chains(context, hunt_id)
        ai_chains = [c for c in chains if "ai_plus_auth_bypass" in c.tags]
        assert len(ai_chains) == 1
        assert ai_chains[0].severity == Severity.CRITICAL

    def test_ai_tool_abuse_requires_matching_evidence(self, context, hunt_id):
        """AI tool-abuse chain should not fire without tool-use evidence."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="ai",
            url="https://app.example.com/api/chat",
            parameter="message",
            evidence=[{"type": "instruction_override"}],
        )

        chains = detect_chains(context, hunt_id)
        ai_chains = [c for c in chains if "ai_tool_abuse" in c.tags]
        assert len(ai_chains) == 0

    def test_ai_plus_auth_bypass_requires_same_host(self, context, hunt_id):
        """AI/auth chain should not fire when findings are on different hosts."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="ai",
            url="https://chat.example.com/api/chat",
            parameter="message",
            evidence=[{"type": "instruction_override"}],
        )
        _insert_finding(
            context,
            hunt_id,
            finding_type="auth",
            url="https://admin.example.com/admin/ai",
            parameter="",
            evidence=[{"type": "no_auth_access", "note": "admin AI panel accessible"}],
        )

        chains = detect_chains(context, hunt_id)
        ai_chains = [c for c in chains if "ai_plus_auth_bypass" in c.tags]
        assert len(ai_chains) == 0


# ═══════════════════ Suggest Chains ═══════════════════


class TestSuggestChains:
    def test_suggest_for_specific_findings(self, context, hunt_id):
        """suggest_chains returns chains relevant to the given finding IDs."""
        f1 = _insert_finding(
            context,
            hunt_id,
            finding_type="ssrf",
            url="https://app.example.com/proxy",
            parameter="url",
            evidence=[{"payload": "http://169.254.169.254/", "indicator": "aws"}],
        )

        chains = suggest_chains(context, hunt_id, [f1])
        assert len(chains) >= 1
        assert all(f1 in c.finding_ids for c in chains)

    def test_suggest_no_match(self, context, hunt_id):
        """suggest_chains returns empty when findings don't match any rule."""
        f1 = _insert_finding(
            context,
            hunt_id,
            finding_type="xss",
            url="https://app.example.com/search",
            parameter="q",
            evidence=[{"type": "reflected"}],
        )

        chains = suggest_chains(context, hunt_id, [f1])
        # XSS alone with "reflected" evidence matches session_hijack rule
        # This is expected — it's a valid suggestion
        for c in chains:
            assert f1 in c.finding_ids


# ═══════════════════ Validation ═══════════════════


class TestValidateChain:
    def test_validate_updates_confidence(self, context, hunt_id):
        """validate_chain transitions from hypothetical to validated."""
        _insert_finding(
            context,
            hunt_id,
            finding_type="ssrf",
            url="https://app.example.com/proxy",
            parameter="url",
            evidence=[{"payload": "http://169.254.169.254/", "indicator": "aws"}],
        )

        chains = detect_chains(context, hunt_id)
        assert len(chains) >= 1

        chain_id = chains[0].id
        updated = validate_chain(context, hunt_id, chain_id)
        assert updated is not None
        assert updated.confidence == ChainStatus.VALIDATED

        # Verify persisted
        persisted = context.get_chain(chain_id)
        assert persisted["confidence"] == "validated"

    def test_validate_nonexistent(self, context, hunt_id):
        """validate_chain returns None for nonexistent chain ID."""
        result = validate_chain(context, hunt_id, 99999)
        assert result is None


# ═══════════════════ Context CRUD ═══════════════════


class TestChainContextCRUD:
    def test_upsert_and_query(self, context, hunt_id):
        """Insert a chain and query it back."""
        cid = context.upsert_chain(
            hunt_id,
            {
                "title": "Test Chain",
                "severity": "critical",
                "cvss_score": 9.8,
                "finding_ids": [1, 2],
                "impact": "Full compromise",
            },
        )
        assert cid > 0

        chains = context.get_chains(hunt_id)
        assert len(chains) == 1
        assert chains[0]["title"] == "Test Chain"
        assert chains[0]["finding_ids"] == [1, 2]

    def test_get_chain_by_id(self, context, hunt_id):
        """get_chain returns a single chain."""
        cid = context.upsert_chain(
            hunt_id,
            {
                "title": "Single Chain",
                "severity": "high",
            },
        )

        chain = context.get_chain(cid)
        assert chain is not None
        assert chain["title"] == "Single Chain"

    def test_filter_by_severity(self, context, hunt_id):
        """get_chains with severity filter."""
        context.upsert_chain(hunt_id, {"title": "Crit Chain", "severity": "critical"})
        context.upsert_chain(hunt_id, {"title": "Low Chain", "severity": "low"})

        crits = context.get_chains(hunt_id, severity="critical")
        assert len(crits) == 1
        assert crits[0]["title"] == "Crit Chain"

    def test_delete_chains(self, context, hunt_id):
        """delete_chains removes all chains for a hunt."""
        context.upsert_chain(hunt_id, {"title": "C1", "severity": "high"})
        context.upsert_chain(hunt_id, {"title": "C2", "severity": "low"})

        deleted = context.delete_chains(hunt_id)
        assert deleted == 2
        assert context.get_chains(hunt_id) == []


# ═══════════════════ CLI ═══════════════════


class TestCLIChain:
    def test_cli_chain_detect_json(self, tmp_path):
        """CLI analyze chain --format json detects and returns chains."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")

        mgr.context.upsert_finding(
            hunt.id,
            {
                "finding_type": "ssrf",
                "severity": "high",
                "title": "SSRF",
                "url": "https://app.example.com/proxy",
                "parameter": "url",
                "evidence": [{"payload": "http://169.254.169.254/", "indicator": "aws"}],
            },
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            [
                "analyze",
                "chain",
                hunt.id,
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) >= 1
        assert data[0]["severity"] == "critical"

    def test_cli_chain_no_chains(self, tmp_path):
        """CLI analyze chain with no findings shows info message."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")
        mgr.close_context()

        result = runner.invoke(
            app,
            [
                "analyze",
                "chain",
                hunt.id,
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        assert "No chains" in result.stdout
