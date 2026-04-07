"""Tests for report drafting — structure, evidence, chain reports."""

from __future__ import annotations

import pytest

from boba.core.models import Hunt, ReportStatus, ScopeConfig
from boba.reporting.draft import draft_chain_report, draft_finding_report


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="report_test_001", name="Report Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


def _insert_finding(context, hunt_id, **kwargs):
    return context.upsert_finding(
        hunt_id,
        {
            "finding_type": kwargs.get("finding_type", "xss"),
            "severity": kwargs.get("severity", "medium"),
            "title": kwargs.get("title", "XSS on /search"),
            "url": kwargs.get("url", "https://app.example.com/search"),
            "parameter": kwargs.get("parameter", "q"),
            "evidence": kwargs.get("evidence"),
            "request_ids": kwargs.get("request_ids", []),
        },
    )


class TestDraftFindingReport:
    def test_report_structure(self, context, hunt_id):
        """Draft has all required fields populated."""
        fid = _insert_finding(
            context,
            hunt_id,
            finding_type="sqli",
            evidence=[{"type": "error_based", "payload": "' OR 1=1--"}],
        )

        draft = draft_finding_report(context, hunt_id, fid)

        assert draft.id > 0
        assert draft.finding_id == fid
        assert draft.title  # non-empty
        assert draft.summary  # non-empty
        assert draft.impact  # non-empty
        assert draft.remediation  # non-empty
        assert len(draft.steps) >= 2
        assert draft.cvss_score > 0
        assert "CVSS:3.1/" in draft.cvss_vector
        assert draft.status == ReportStatus.DRAFT

    def test_title_format(self, context, hunt_id):
        """Title follows [Component] [Vuln Type] leads to [Impact] pattern."""
        fid = _insert_finding(
            context,
            hunt_id,
            finding_type="idor",
            url="https://app.example.com/api/users",
            parameter="id",
        )

        draft = draft_finding_report(context, hunt_id, fid)

        assert "api/users" in draft.title.lower() or "api" in draft.title.lower()
        assert "idor" in draft.title.lower() or "object reference" in draft.title.lower()

    def test_includes_evidence_in_steps(self, context, hunt_id):
        """Evidence payloads appear in reproduction steps."""
        fid = _insert_finding(
            context, hunt_id, finding_type="sqli", evidence=[{"payload": "' OR 1=1--"}]
        )

        draft = draft_finding_report(context, hunt_id, fid)

        steps_text = " ".join(draft.steps)
        assert "' OR 1=1--" in steps_text

    def test_persists_to_reports_table(self, context, hunt_id):
        """Draft is saved and retrievable from reports table."""
        fid = _insert_finding(context, hunt_id)

        draft = draft_finding_report(context, hunt_id, fid)

        reports = context.get_reports(hunt_id)
        assert len(reports) == 1
        assert reports[0]["id"] == draft.id
        assert reports[0]["status"] == "draft"

    def test_nonexistent_finding_raises(self, context, hunt_id):
        """Drafting a report for nonexistent finding raises ValueError."""
        with pytest.raises(ValueError, match="not found"):
            draft_finding_report(context, hunt_id, 99999)


class TestDraftChainReport:
    def test_chain_report_merges_findings(self, context, hunt_id):
        """Chain report merges steps from all chained findings."""
        f1 = _insert_finding(
            context,
            hunt_id,
            finding_type="idor",
            url="https://app.example.com/api/users",
            parameter="id",
        )
        f2 = _insert_finding(
            context,
            hunt_id,
            finding_type="sqli",
            url="https://app.example.com/api/search",
            parameter="q",
            evidence=[{"type": "error_based"}],
        )

        chain_id = context.upsert_chain(
            hunt_id,
            {
                "title": "IDOR + SQLi Chain",
                "severity": "critical",
                "cvss_score": 9.8,
                "finding_ids": [f1, f2],
                "impact": "Full data exfiltration",
            },
        )

        draft = draft_chain_report(context, hunt_id, chain_id)

        assert draft.chain_id == chain_id
        assert "chain" in draft.summary.lower() or "2 findings" in draft.summary.lower()
        assert len(draft.steps) >= 2  # at least one step per finding

    def test_nonexistent_chain_raises(self, context, hunt_id):
        """Drafting a chain report for nonexistent chain raises ValueError."""
        with pytest.raises(ValueError, match="not found"):
            draft_chain_report(context, hunt_id, 99999)
