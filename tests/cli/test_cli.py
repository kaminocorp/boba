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
