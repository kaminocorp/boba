"""Tests for V3 severity assessment — CVSS 3.1 calculator, auto-scoring, payouts, CLI."""

from __future__ import annotations

import json

import pytest

from boba.analysis.severity import (
    auto_score_finding,
    calculate_cvss,
    estimate_payout,
    score_findings,
    severity_from_score,
)
from boba.core.models import Hunt, Severity, ScopeConfig


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="sev_test_001", name="Severity Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


def _insert_finding(context, hunt_id, **kwargs):
    """Helper to insert a finding and return its ID."""
    finding = {
        "finding_type": kwargs.get("finding_type", "xss"),
        "severity": kwargs.get("severity", "medium"),
        "title": kwargs.get("title", "Test Finding"),
        "url": kwargs.get("url", "https://app.example.com/search"),
        "parameter": kwargs.get("parameter", "q"),
        "evidence": kwargs.get("evidence"),
    }
    return context.upsert_finding(hunt_id, finding)


# ═══════════════════ CVSS Calculator ═══════════════════


class TestCVSSCalculation:
    def test_max_score_10(self):
        """All-high metrics with scope changed → CVSS 10.0 (Log4Shell-like)."""
        result = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        assert result.score == 10.0
        assert result.severity == Severity.CRITICAL
        assert "CVSS:3.1/" in result.vector

    def test_zero_impact(self):
        """All CIA = None → score 0.0."""
        result = calculate_cvss(
            confidentiality="N",
            integrity="N",
            availability="N",
        )
        assert result.score == 0.0
        assert result.severity == Severity.INFO

    def test_known_vector_cve_2021_44228(self):
        """Log4Shell CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0."""
        result = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        assert result.score == 10.0

    def test_known_vector_medium(self):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 (reflected XSS)."""
        result = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="C",
            confidentiality="L",
            integrity="L",
            availability="N",
        )
        assert result.score == 6.1

    def test_physical_access_low_score(self):
        """Physical attack vector with low impact → low score."""
        result = calculate_cvss(
            attack_vector="P",
            attack_complexity="H",
            privileges_required="H",
            user_interaction="R",
            scope="U",
            confidentiality="L",
            integrity="N",
            availability="N",
        )
        assert result.score < 2.0
        assert result.severity == Severity.LOW

    def test_scope_unchanged_vs_changed(self):
        """Scope:Changed produces higher score than Scope:Unchanged for same metrics."""
        unchanged = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="L",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="N",
            availability="N",
        )
        changed = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="L",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="N",
            availability="N",
        )
        assert changed.score > unchanged.score

    def test_vector_string_format(self):
        """Vector string matches CVSS 3.1 format."""
        result = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="N",
        )
        assert result.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"


# ═══════════════════ Severity from score ═══════════════════


class TestSeverityFromScore:
    def test_boundaries(self):
        """Score boundaries map correctly."""
        assert severity_from_score(0.0) == Severity.INFO
        assert severity_from_score(0.1) == Severity.LOW
        assert severity_from_score(3.9) == Severity.LOW
        assert severity_from_score(4.0) == Severity.MEDIUM
        assert severity_from_score(6.9) == Severity.MEDIUM
        assert severity_from_score(7.0) == Severity.HIGH
        assert severity_from_score(8.9) == Severity.HIGH
        assert severity_from_score(9.0) == Severity.CRITICAL
        assert severity_from_score(10.0) == Severity.CRITICAL


# ═══════════════════ Auto-scoring ═══════════════════


class TestAutoScoring:
    def test_idor_default(self):
        """IDOR auto-scores as high (read access)."""
        result = auto_score_finding({"finding_type": "idor"})
        assert result.severity in (Severity.HIGH, Severity.MEDIUM)
        assert result.confidentiality == "H"

    def test_idor_write_higher(self):
        """IDOR with write evidence → integrity:H."""
        result = auto_score_finding(
            {
                "finding_type": "idor",
                "evidence": [{"method": "DELETE", "note": "Deleted resource"}],
            }
        )
        assert result.integrity == "H"

    def test_ssrf_cloud_metadata(self):
        """SSRF with cloud metadata evidence → critical."""
        result = auto_score_finding(
            {
                "finding_type": "ssrf",
                "evidence": [{"payload": "http://169.254.169.254/latest/meta-data/"}],
            }
        )
        assert result.severity == Severity.CRITICAL
        assert result.scope == "C"

    def test_xss_reflected_vs_stored(self):
        """Stored XSS scores higher than reflected."""
        reflected = auto_score_finding(
            {
                "finding_type": "xss",
                "evidence": [{"type": "reflected"}],
            }
        )
        stored = auto_score_finding(
            {
                "finding_type": "xss",
                "evidence": [{"type": "stored"}],
            }
        )
        assert stored.score >= reflected.score

    def test_sqli_default_critical(self):
        """SQLi auto-scores as critical (AV:N/AC:L/PR:N/UI:N → C:H/I:H)."""
        result = auto_score_finding({"finding_type": "sqli"})
        assert result.severity == Severity.CRITICAL
        assert result.confidentiality == "H"
        assert result.integrity == "H"

    def test_auth_default_critical(self):
        """Auth bypass auto-scores as critical (AV:N/AC:L/PR:N/UI:N → C:H/I:H)."""
        result = auto_score_finding({"finding_type": "auth"})
        assert result.severity == Severity.CRITICAL

    def test_unknown_type_fallback(self):
        """Unknown finding type gets a safe default score."""
        result = auto_score_finding({"finding_type": "unknown_custom_type"})
        assert result.score > 0
        assert result.severity in (Severity.LOW, Severity.MEDIUM)


# ═══════════════════ Payout mapping ═══════════════════


class TestPayoutMapping:
    def test_hackerone_critical(self):
        """HackerOne critical payout range."""
        pmin, pmax = estimate_payout(Severity.CRITICAL, "hackerone")
        assert pmin == 5_000
        assert pmax == 50_000

    def test_bugcrowd_high(self):
        """Bugcrowd high (P2) payout range."""
        pmin, pmax = estimate_payout(Severity.HIGH, "bugcrowd")
        assert pmin == 2_500
        assert pmax == 7_500

    def test_info_zero_payout(self):
        """Info severity pays nothing."""
        pmin, pmax = estimate_payout(Severity.INFO, "hackerone")
        assert pmin == 0
        assert pmax == 0

    def test_unknown_platform_fallback(self):
        """Unknown platform falls back to HackerOne tiers."""
        pmin, pmax = estimate_payout(Severity.HIGH, "unknown_platform")
        assert pmin == 2_500  # HackerOne high


# ═══════════════════ Batch scoring ═══════════════════


class TestBatchScoring:
    def test_score_all_findings(self, context, hunt_id):
        """score_findings scores all findings in a hunt."""
        _insert_finding(context, hunt_id, finding_type="idor", title="IDOR 1")
        _insert_finding(
            context,
            hunt_id,
            finding_type="xss",
            title="XSS 1",
            url="https://app.example.com/other",
            parameter="p",
        )

        scored = score_findings(context, hunt_id)
        assert len(scored) == 2
        assert all("cvss_score" in s for s in scored)
        assert all("cvss_vector" in s for s in scored)

    def test_score_specific_finding(self, context, hunt_id):
        """score_findings with finding_ids filters to specific findings."""
        f1 = _insert_finding(context, hunt_id, finding_type="idor", title="IDOR 1")
        _insert_finding(
            context,
            hunt_id,
            finding_type="xss",
            title="XSS 1",
            url="https://app.example.com/other",
            parameter="p",
        )

        scored = score_findings(context, hunt_id, finding_ids=[f1])
        assert len(scored) == 1
        assert scored[0]["finding_id"] == f1

    def test_score_with_platform(self, context, hunt_id):
        """score_findings with platform includes payout estimates."""
        _insert_finding(context, hunt_id, finding_type="sqli", title="SQLi 1")

        scored = score_findings(context, hunt_id, platform="hackerone")
        assert len(scored) == 1
        assert "payout_min" in scored[0]
        assert "payout_max" in scored[0]
        assert scored[0]["platform"] == "hackerone"

    def test_score_empty_hunt(self, context, hunt_id):
        """score_findings on a hunt with no findings returns empty list."""
        scored = score_findings(context, hunt_id)
        assert scored == []


# ═══════════════════ CLI ═══════════════════


class TestCLISeverity:
    def test_cli_severity_json(self, tmp_path):
        """CLI analyze severity --format json produces valid JSON."""
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
                "finding_type": "sqli",
                "severity": "high",
                "title": "SQLi on /search",
                "url": "https://app.example.com/search",
                "parameter": "q",
            },
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            [
                "analyze",
                "severity",
                hunt.id,
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) == 1
        assert data[0]["cvss_score"] > 0
        assert "CVSS:3.1/" in data[0]["cvss_vector"]

    def test_cli_severity_with_platform(self, tmp_path):
        """CLI analyze severity --platform hackerone includes payout."""
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
                "finding_type": "idor",
                "severity": "high",
                "title": "IDOR",
                "url": "https://app.example.com/api",
                "parameter": "id",
            },
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            [
                "analyze",
                "severity",
                hunt.id,
                "--platform",
                "hackerone",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data[0]["payout_min"] > 0

    def test_cli_severity_no_findings(self, tmp_path):
        """CLI analyze severity with no findings shows info message."""
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
                "severity",
                hunt.id,
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        assert "No findings" in result.stdout
