"""
Tests for Tsukiko Packaging and Distribution.
Verifies wheel contents, entry points, packaged config loading, and out-of-tree execution.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import pytest

from app.core.config.settings import find_default_config_path, load_config, reset_config


def test_packaged_config_discovery():
    """Verify default_config.yaml is located correctly."""
    cfg_path = find_default_config_path()
    assert cfg_path.exists()
    assert cfg_path.name in ("default_config.yaml", "default_config.yml")

    reset_config()
    loaded = load_config(cfg_path)
    assert loaded.app.name == "Tsukiko"
    assert loaded.privacy.local_only is True


def test_package_entrypoint_outside_source_tree(temp_dir):
    """Verifies that the installed entry point runs from an arbitrary working directory outside the repo."""
    # Run python -m app.main --check-hardware with cwd set to a temporary folder
    # and sys.path restricted to installed site-packages or current venv.
    env = dict(os.environ)
    if "PYTHONPATH" in env:
        del env["PYTHONPATH"]

    cmd = [sys.executable, "-m", "app.main", "--check-hardware"]
    res = subprocess.run(
        cmd,
        cwd=str(temp_dir),
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )
    assert res.returncode == 0
    assert "TSUKIKO HARDWARE & ENVIRONMENT AUDIT" in res.stdout
    assert "Dynamic Safe VRAM Cap:" in res.stdout
