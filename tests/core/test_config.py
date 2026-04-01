"""Tests for boba.core.config — data directory helpers."""

from __future__ import annotations

from pathlib import Path

from boba.core.config import (
    get_bodies_dir,
    get_data_dir,
    get_db_path,
    get_hunt_dir,
    get_templates_dir,
    get_tmp_dir,
)


def test_default_data_dir(monkeypatch, tmp_path):
    """get_data_dir() defaults to ~/.boba when BOBA_DATA_DIR is unset."""
    monkeypatch.delenv("BOBA_DATA_DIR", raising=False)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    result = get_data_dir()
    assert result == tmp_path / ".boba"
    assert result.is_dir()


def test_data_dir_env_override(monkeypatch, tmp_path):
    """BOBA_DATA_DIR env var overrides the default data directory."""
    custom_dir = tmp_path / "custom_data"
    monkeypatch.setenv("BOBA_DATA_DIR", str(custom_dir))

    result = get_data_dir()
    assert result == custom_dir
    assert result.is_dir()


def test_get_db_path(monkeypatch, tmp_path):
    """get_db_path() returns data_dir / 'boba.db'."""
    monkeypatch.setenv("BOBA_DATA_DIR", str(tmp_path))

    result = get_db_path()
    assert result == tmp_path / "boba.db"
    assert result.parent.is_dir()


def test_get_tmp_dir_creates_directory(monkeypatch, tmp_path):
    """get_tmp_dir() creates and returns data_dir / 'tmp'."""
    monkeypatch.setenv("BOBA_DATA_DIR", str(tmp_path))

    result = get_tmp_dir()
    assert result == tmp_path / "tmp"
    assert result.is_dir()


def test_get_hunt_dir_creates_nested_directory(monkeypatch, tmp_path):
    """get_hunt_dir() creates data_dir / 'hunts' / hunt_id."""
    monkeypatch.setenv("BOBA_DATA_DIR", str(tmp_path))

    result = get_hunt_dir("test-hunt-42")
    assert result == tmp_path / "hunts" / "test-hunt-42"
    assert result.is_dir()


def test_get_bodies_dir_creates_subdirectory(monkeypatch, tmp_path):
    """get_bodies_dir() creates hunt_dir / 'bodies'."""
    monkeypatch.setenv("BOBA_DATA_DIR", str(tmp_path))

    result = get_bodies_dir("hunt-abc")
    assert result == tmp_path / "hunts" / "hunt-abc" / "bodies"
    assert result.is_dir()


def test_get_templates_dir_creates_subdirectory(monkeypatch, tmp_path):
    """get_templates_dir() creates hunt_dir / 'templates'."""
    monkeypatch.setenv("BOBA_DATA_DIR", str(tmp_path))

    result = get_templates_dir("hunt-abc")
    assert result == tmp_path / "hunts" / "hunt-abc" / "templates"
    assert result.is_dir()
