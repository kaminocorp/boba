"""Tests for report CLI commands."""

from __future__ import annotations

import json


class TestCLIReportDraft:
    def test_draft_finding_json(self, tmp_path):
        """CLI report draft --finding-id produces valid JSON."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")

        fid = mgr.context.upsert_finding(hunt.id, {
            "finding_type": "sqli", "severity": "high",
            "title": "SQLi", "url": "https://app.example.com/search",
            "parameter": "q",
            "evidence": [{"type": "error_based", "payload": "' OR 1=1--"}],
        })
        mgr.close_context()

        result = runner.invoke(app, [
            "report", "draft", hunt.id,
            "--finding-id", str(fid),
            "--format", "json",
            "--data-dir", str(tmp_path),
        ])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["finding_id"] == fid
        assert data["title"]
        assert data["cvss_score"] > 0

    def test_draft_requires_id(self, tmp_path):
        """CLI report draft without --finding-id or --chain-id fails."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")
        mgr.close_context()

        result = runner.invoke(app, [
            "report", "draft", hunt.id,
            "--data-dir", str(tmp_path),
        ])
        assert result.exit_code == 1


class TestCLIReportFormat:
    def test_format_hackerone(self, tmp_path):
        """CLI report format --platform hackerone produces HackerOne markdown."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")

        fid = mgr.context.upsert_finding(hunt.id, {
            "finding_type": "xss", "severity": "medium",
            "title": "XSS", "url": "https://app.example.com/search",
            "parameter": "q",
        })
        # Create a report first
        mgr.context.upsert_report(hunt.id, {
            "finding_id": fid,
            "title": "XSS on search",
            "severity": "medium",
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "summary": "XSS found",
            "steps": ["Navigate to /search", "Inject payload"],
            "impact": "Script execution",
            "remediation": "Encode output",
            "status": "draft",
        })
        mgr.close_context()

        result = runner.invoke(app, [
            "report", "format", hunt.id,
            "--report-id", "1",
            "--platform", "hackerone",
            "--data-dir", str(tmp_path),
        ])
        assert result.exit_code == 0
        assert "### Summary" in result.stdout
        assert "### Steps to Reproduce" in result.stdout


class TestCLIReportList:
    def test_list_reports(self, tmp_path):
        """CLI report list shows reports."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")

        fid = mgr.context.upsert_finding(hunt.id, {
            "finding_type": "xss", "severity": "high",
            "title": "Stored XSS", "url": "https://app.example.com/comment",
            "parameter": "body",
        })
        mgr.context.upsert_report(hunt.id, {
            "finding_id": fid,
            "title": "Test Report", "severity": "high", "status": "draft",
        })
        mgr.close_context()

        result = runner.invoke(app, [
            "report", "list", hunt.id,
            "--format", "json",
            "--data-dir", str(tmp_path),
        ])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) == 1
        assert data[0]["title"] == "Test Report"
