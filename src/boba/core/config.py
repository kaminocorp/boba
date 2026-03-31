"""Global configuration for Boba."""

from __future__ import annotations

import os
from pathlib import Path


def get_data_dir() -> Path:
    """Return the Boba data directory, creating it if needed."""
    data_dir = Path(os.environ.get("BOBA_DATA_DIR", Path.home() / ".boba"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_db_path() -> Path:
    """Return the path to the main SQLite database."""
    return get_data_dir() / "boba.db"


def get_tmp_dir() -> Path:
    """Return the temp directory for tool I/O files."""
    tmp_dir = get_data_dir() / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    return tmp_dir


def get_hunt_dir(hunt_id: str) -> Path:
    """Return the per-hunt data directory, creating it if needed."""
    hunt_dir = get_data_dir() / "hunts" / hunt_id
    hunt_dir.mkdir(parents=True, exist_ok=True)
    return hunt_dir


def get_bodies_dir(hunt_id: str) -> Path:
    """Return the directory for large HTTP body storage."""
    bodies_dir = get_hunt_dir(hunt_id) / "bodies"
    bodies_dir.mkdir(parents=True, exist_ok=True)
    return bodies_dir


def get_templates_dir(hunt_id: str) -> Path:
    """Return the directory for custom Nuclei templates."""
    templates_dir = get_hunt_dir(hunt_id) / "templates"
    templates_dir.mkdir(parents=True, exist_ok=True)
    return templates_dir
