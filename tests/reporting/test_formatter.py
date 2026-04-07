"""Tests for platform-specific report formatting."""

from __future__ import annotations

import pytest

from boba.core.models import ReportDraft, ReportStatus, Severity
from boba.reporting.formatter import format_bugcrowd, format_hackerone, format_markdown


@pytest.fixture
def sample_report():
    return ReportDraft(
        id=1,
        hunt_id="fmt_test_001",
        finding_id=1,
        title="api/users — Insecure Direct Object Reference via `id` Parameter Leads to Unauthorized Data Access",
        severity=Severity.HIGH,
        cvss_score=7.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        summary="An IDOR vulnerability was identified at /api/users allowing unauthorized data access.",
        steps=[
            "Navigate to https://app.example.com/api/users/123",
            "Inject payload: change ID to 124",
            "Observe: User B can access User A's data",
        ],
        impact="An authenticated attacker can access other users' data.",
        remediation="Implement server-side authorization checks on every resource access.",
        evidence_refs=["evidence/001_request.http"],
        status=ReportStatus.DRAFT,
    )


class TestHackerOneFormat:
    def test_has_required_sections(self, sample_report):
        """HackerOne format contains all required sections."""
        output = format_hackerone(sample_report)

        assert "## " in output  # title
        assert "**Severity:**" in output
        assert "**CVSS Score:**" in output
        assert "### Summary" in output
        assert "### Steps to Reproduce" in output
        assert "### Impact" in output
        assert "### Remediation" in output

    def test_steps_numbered(self, sample_report):
        """Steps are numbered in output."""
        output = format_hackerone(sample_report)

        assert "1. Navigate" in output
        assert "2. Inject" in output
        assert "3. Observe" in output

    def test_cvss_vector_included(self, sample_report):
        """CVSS vector string is in the output."""
        output = format_hackerone(sample_report)
        assert "CVSS:3.1/AV:N" in output

    def test_evidence_refs_listed(self, sample_report):
        """Evidence references appear in Supporting Material."""
        output = format_hackerone(sample_report)
        assert "evidence/001_request.http" in output


class TestBugcrowdFormat:
    def test_has_vrt(self, sample_report):
        """Bugcrowd format includes VRT classification."""
        output = format_bugcrowd(sample_report)
        assert "**VRT:**" in output
        assert "P2" in output  # HIGH maps to P2

    def test_has_severity_justification(self, sample_report):
        """Bugcrowd format includes CVSS severity justification."""
        output = format_bugcrowd(sample_report)
        assert "### Severity Justification" in output
        assert "7.1" in output


class TestMarkdownFormat:
    def test_valid_markdown_structure(self, sample_report):
        """Generic markdown has proper heading structure."""
        output = format_markdown(sample_report)

        assert output.startswith("# ")
        assert "## Summary" in output
        assert "## Steps to Reproduce" in output
        assert "## Impact" in output
        assert "## CVSS Details" in output

    def test_no_cvss_section_without_vector(self):
        """No CVSS Details section when vector is empty."""
        report = ReportDraft(
            title="Test",
            severity=Severity.LOW,
            summary="test",
            impact="test",
        )
        output = format_markdown(report)
        assert "## CVSS Details" not in output
