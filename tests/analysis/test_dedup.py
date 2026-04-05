"""Tests for V3 finding deduplication — engine logic, context CRUD, canonical selection, CLI."""

from __future__ import annotations

import json

import pytest

from boba.analysis.dedup import check_duplicate, deduplicate_findings
from boba.core.models import Hunt, ScopeConfig


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="dedup_test_001", name="Dedup Test", scope=ScopeConfig())
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
        "confirmed": kwargs.get("confirmed", False),
    }
    return context.upsert_finding(hunt_id, finding)


# ═══════════════════ Context CRUD ═══════════════════


class TestDedupGroupCRUD:
    def test_insert_and_query(self, context, hunt_id):
        """Insert a dedup group and query it back."""
        f1 = _insert_finding(context, hunt_id, title="Finding 1")
        f2 = _insert_finding(context, hunt_id, title="Finding 2", url="https://app.example.com/search2")

        gid = context.insert_dedup_group(hunt_id, {
            "canonical_id": f1,
            "finding_ids": [f1, f2],
            "reason": "Same param on same host",
        })
        assert gid > 0

        groups = context.get_dedup_groups(hunt_id)
        assert len(groups) == 1
        assert groups[0]["canonical_id"] == f1
        assert groups[0]["finding_ids"] == [f1, f2]

    def test_delete_dedup_groups(self, context, hunt_id):
        """delete_dedup_groups clears all groups for a hunt."""
        f1 = _insert_finding(context, hunt_id, title="F1")
        context.insert_dedup_group(hunt_id, {
            "canonical_id": f1,
            "finding_ids": [f1],
            "reason": "test",
        })

        deleted = context.delete_dedup_groups(hunt_id)
        assert deleted == 1
        assert context.get_dedup_groups(hunt_id) == []

    def test_is_duplicate(self, context, hunt_id):
        """is_duplicate returns True for non-canonical members."""
        f1 = _insert_finding(context, hunt_id, title="Canonical", url="https://a.com/1")
        f2 = _insert_finding(context, hunt_id, title="Dupe", url="https://a.com/2")

        context.insert_dedup_group(hunt_id, {
            "canonical_id": f1,
            "finding_ids": [f1, f2],
            "reason": "test",
        })

        assert context.is_duplicate(hunt_id, f2) is True
        assert context.is_duplicate(hunt_id, f1) is False

    def test_get_canonical_finding(self, context, hunt_id):
        """get_canonical_finding returns the canonical for a grouped finding."""
        f1 = _insert_finding(context, hunt_id, title="Canonical", url="https://a.com/1")
        f2 = _insert_finding(context, hunt_id, title="Dupe", url="https://a.com/2")

        context.insert_dedup_group(hunt_id, {
            "canonical_id": f1,
            "finding_ids": [f1, f2],
            "reason": "test",
        })

        canonical = context.get_canonical_finding(hunt_id, f2)
        assert canonical is not None
        assert canonical["id"] == f1

    def test_get_canonical_finding_ungrouped(self, context, hunt_id):
        """get_canonical_finding returns the finding itself if not in a group."""
        f1 = _insert_finding(context, hunt_id, title="Solo", url="https://solo.com/1")

        result = context.get_canonical_finding(hunt_id, f1)
        assert result is not None
        assert result["id"] == f1


# ═══════════════════ Dedup Engine ═══════════════════


class TestDeduplicateFindings:
    def test_exact_url_param_dedup(self, context, hunt_id):
        """Same URL + param from different finding types → grouped."""
        _insert_finding(
            context, hunt_id, finding_type="sqli",
            url="https://app.example.com/search", parameter="q",
            title="SQLi on search",
        )
        _insert_finding(
            context, hunt_id, finding_type="http",  # Nuclei finding type
            url="https://app.example.com/search", parameter="q",
            title="Nuclei SQLi template match",
        )

        groups = deduplicate_findings(context, hunt_id)
        assert len(groups) == 1
        assert len(groups[0].finding_ids) == 2

    def test_same_host_param_vuln_class(self, context, hunt_id):
        """Same host + param + vuln class across different API versions → grouped."""
        _insert_finding(
            context, hunt_id, finding_type="idor",
            url="https://app.example.com/api/v1/users", parameter="id",
            title="IDOR on v1 users",
        )
        _insert_finding(
            context, hunt_id, finding_type="idor",
            url="https://app.example.com/api/v2/users", parameter="id",
            title="IDOR on v2 users",
        )

        groups = deduplicate_findings(context, hunt_id)
        assert len(groups) == 1
        assert len(groups[0].finding_ids) == 2

    def test_no_false_dedup_different_params(self, context, hunt_id):
        """Different params on same URL → NOT grouped."""
        _insert_finding(
            context, hunt_id, finding_type="xss",
            url="https://app.example.com/search", parameter="q",
            title="XSS on q",
        )
        _insert_finding(
            context, hunt_id, finding_type="xss",
            url="https://app.example.com/search", parameter="lang",
            title="XSS on lang",
        )

        groups = deduplicate_findings(context, hunt_id)
        assert len(groups) == 0

    def test_no_false_dedup_different_hosts(self, context, hunt_id):
        """Same param + vuln class but different hosts → NOT grouped."""
        _insert_finding(
            context, hunt_id, finding_type="xss",
            url="https://app1.example.com/search", parameter="q",
            title="XSS on app1",
        )
        _insert_finding(
            context, hunt_id, finding_type="xss",
            url="https://app2.example.com/search", parameter="q",
            title="XSS on app2",
        )

        groups = deduplicate_findings(context, hunt_id)
        assert len(groups) == 0

    def test_canonical_selection_confirmed_wins(self, context, hunt_id):
        """Confirmed finding is selected as canonical over unconfirmed."""
        _insert_finding(
            context, hunt_id, finding_type="idor",
            url="https://app.example.com/api/users", parameter="id",
            title="IDOR unconfirmed", confirmed=False, severity="high",
        )
        _insert_finding(
            context, hunt_id, finding_type="idor",
            url="https://app.example.com/api/v2/users", parameter="id",
            title="IDOR confirmed", confirmed=True, severity="medium",
        )

        groups = deduplicate_findings(context, hunt_id)
        assert len(groups) == 1
        canonical = context.get_finding_by_id(groups[0].canonical_id)
        assert canonical["title"] == "IDOR confirmed"

    def test_canonical_selection_severity_tiebreak(self, context, hunt_id):
        """When confidence is equal, higher severity wins."""
        _insert_finding(
            context, hunt_id, finding_type="ssrf",
            url="https://app.example.com/proxy", parameter="url",
            title="SSRF medium", severity="medium",
        )
        _insert_finding(
            context, hunt_id, finding_type="ssrf",
            url="https://app.example.com/api/proxy", parameter="url",
            title="SSRF critical", severity="critical",
        )

        groups = deduplicate_findings(context, hunt_id)
        assert len(groups) == 1
        canonical = context.get_finding_by_id(groups[0].canonical_id)
        assert canonical["title"] == "SSRF critical"

    def test_idempotent(self, context, hunt_id):
        """Running deduplicate_findings twice doesn't create duplicate groups."""
        _insert_finding(
            context, hunt_id, finding_type="xss",
            url="https://app.example.com/a", parameter="q",
        )
        _insert_finding(
            context, hunt_id, finding_type="xss",
            url="https://app.example.com/b", parameter="q",
        )

        groups1 = deduplicate_findings(context, hunt_id)
        groups2 = deduplicate_findings(context, hunt_id)
        assert len(groups1) == len(groups2)

        all_groups = context.get_dedup_groups(hunt_id)
        assert len(all_groups) == 1  # not 2

    def test_dry_run_does_not_persist(self, context, hunt_id):
        """dry_run=True returns groups but does not write to DB."""
        _insert_finding(
            context, hunt_id, finding_type="xss",
            url="https://app.example.com/a", parameter="q",
        )
        _insert_finding(
            context, hunt_id, finding_type="xss",
            url="https://app.example.com/b", parameter="q",
        )

        groups = deduplicate_findings(context, hunt_id, dry_run=True)
        assert len(groups) == 1

        persisted = context.get_dedup_groups(hunt_id)
        assert len(persisted) == 0

    def test_single_finding_no_groups(self, context, hunt_id):
        """A single finding produces no dedup groups."""
        _insert_finding(context, hunt_id, title="Lone finding")
        groups = deduplicate_findings(context, hunt_id)
        assert len(groups) == 0


# ═══════════════════ Inline check ═══════════════════


class TestCheckDuplicate:
    def test_exact_match(self, context, hunt_id):
        """check_duplicate finds an exact URL+param match."""
        _insert_finding(
            context, hunt_id, finding_type="xss",
            url="https://app.example.com/search", parameter="q",
        )

        result = check_duplicate(context, hunt_id, {
            "finding_type": "xss",
            "url": "https://app.example.com/search",
            "parameter": "q",
        })
        assert result is not None
        assert "Exact URL" in result.reason

    def test_host_param_match(self, context, hunt_id):
        """check_duplicate finds a host+param match on different path."""
        _insert_finding(
            context, hunt_id, finding_type="idor",
            url="https://app.example.com/api/v1/users", parameter="id",
        )

        result = check_duplicate(context, hunt_id, {
            "finding_type": "idor",
            "url": "https://app.example.com/api/v2/users",
            "parameter": "id",
        })
        assert result is not None
        assert "Same host" in result.reason

    def test_no_match(self, context, hunt_id):
        """check_duplicate returns None when no match exists."""
        _insert_finding(
            context, hunt_id, finding_type="xss",
            url="https://app.example.com/search", parameter="q",
        )

        result = check_duplicate(context, hunt_id, {
            "finding_type": "sqli",
            "url": "https://other.example.com/search",
            "parameter": "id",
        })
        assert result is None


# ═══════════════════ CLI ═══════════════════


class TestCLIDedupe:
    def test_cli_dedupe_json(self, tmp_path):
        """CLI analyze dedupe --format json produces valid JSON output."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")

        # Insert two findings that should be deduped (same host + param + type)
        mgr.context.upsert_finding(hunt.id, {
            "finding_type": "xss", "severity": "medium",
            "title": "XSS on /a", "url": "https://app.example.com/a",
            "parameter": "q",
        })
        mgr.context.upsert_finding(hunt.id, {
            "finding_type": "xss", "severity": "high",
            "title": "XSS on /b", "url": "https://app.example.com/b",
            "parameter": "q",
        })
        mgr.close_context()

        result = runner.invoke(app, [
            "analyze", "dedupe", hunt.id,
            "--format", "json",
            "--data-dir", str(tmp_path),
        ])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) == 1
        assert len(data[0]["finding_ids"]) == 2

    def test_cli_dedupe_dry_run(self, tmp_path):
        """CLI analyze dedupe --dry-run shows groups without persisting."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")

        mgr.context.upsert_finding(hunt.id, {
            "finding_type": "idor", "severity": "high",
            "title": "IDOR 1", "url": "https://app.example.com/api/v1",
            "parameter": "id",
        })
        mgr.context.upsert_finding(hunt.id, {
            "finding_type": "idor", "severity": "high",
            "title": "IDOR 2", "url": "https://app.example.com/api/v2",
            "parameter": "id",
        })
        mgr.close_context()

        result = runner.invoke(app, [
            "analyze", "dedupe", hunt.id,
            "--dry-run",
            "--format", "json",
            "--data-dir", str(tmp_path),
        ])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) == 1

        # Verify nothing was persisted
        mgr2 = HuntManager(db_path=db_path)
        assert mgr2.context.get_dedup_groups(hunt.id) == []
        mgr2.close_context()

    def test_cli_dedupe_no_dupes(self, tmp_path):
        """CLI analyze dedupe with no duplicates shows info message."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")
        mgr.close_context()

        result = runner.invoke(app, [
            "analyze", "dedupe", hunt.id,
            "--data-dir", str(tmp_path),
        ])
        assert result.exit_code == 0
        assert "No duplicate" in result.stdout
