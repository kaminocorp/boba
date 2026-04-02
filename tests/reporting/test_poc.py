"""Tests for PoC evidence packaging."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from boba.core.models import Hunt, ScopeConfig
from boba.reporting.poc import package_poc


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="poc_test_001", name="PoC Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


class TestPoCPackaging:
    def test_directory_structure(self, context, hunt_id, tmp_path):
        """PoC creates correct directory structure."""
        fid = context.upsert_finding(hunt_id, {
            "finding_type": "xss", "severity": "medium",
            "title": "XSS on search", "url": "https://app.example.com/search",
            "parameter": "q",
            "evidence": [{"type": "reflected", "payload": "<script>alert(1)</script>"}],
        })

        out = tmp_path / "poc_out"
        package_poc(context, hunt_id, finding_id=fid, output_dir=str(out))

        assert (out / "README.md").exists()
        assert (out / "evidence.json").exists()
        assert (out / "requests").is_dir()

    def test_evidence_json_content(self, context, hunt_id, tmp_path):
        """evidence.json contains the finding's evidence array."""
        evidence = [{"type": "reflected", "payload": "<script>"}]
        fid = context.upsert_finding(hunt_id, {
            "finding_type": "xss", "severity": "medium",
            "title": "XSS", "url": "https://app.example.com/search",
            "parameter": "q",
            "evidence": evidence,
        })

        out = tmp_path / "poc_out"
        package_poc(context, hunt_id, finding_id=fid, output_dir=str(out))

        data = json.loads((out / "evidence.json").read_text())
        assert len(data) == 1
        assert data[0]["type"] == "reflected"

    def test_http_dumps_created(self, context, hunt_id, tmp_path):
        """HTTP history records are written as .http files."""
        # Insert an HTTP history record
        rid = context.insert_http_record(hunt_id, {
            "method": "GET",
            "url": "https://app.example.com/search?q=test",
            "host": "app.example.com",
            "path": "/search",
            "query": "q=test",
            "status_code": 200,
            "response_body": "<html>reflected test</html>",
        })

        fid = context.upsert_finding(hunt_id, {
            "finding_type": "xss", "severity": "medium",
            "title": "XSS", "url": "https://app.example.com/search",
            "parameter": "q",
            "request_ids": [rid],
        })

        out = tmp_path / "poc_out"
        pkg = package_poc(context, hunt_id, finding_id=fid, output_dir=str(out))

        assert len(pkg.http_dumps) == 1
        dump_file = Path(pkg.http_dumps[0]["file"])
        assert dump_file.exists()

        content = dump_file.read_text()
        assert "GET https://app.example.com/search?q=test" in content
        assert "HTTP/1.1 200" in content

    def test_readme_has_summary(self, context, hunt_id, tmp_path):
        """README.md includes the finding title and evidence count."""
        fid = context.upsert_finding(hunt_id, {
            "finding_type": "sqli", "severity": "high",
            "title": "SQL Injection on /api", "url": "https://app.example.com/api",
            "parameter": "id",
            "evidence": [{"type": "error_based"}],
        })

        out = tmp_path / "poc_out"
        package_poc(context, hunt_id, finding_id=fid, output_dir=str(out))

        readme = (out / "README.md").read_text()
        assert "SQL Injection" in readme
        assert "1 evidence" in readme
