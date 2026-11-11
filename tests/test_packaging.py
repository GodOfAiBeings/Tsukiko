"""
Genuine packaging and distribution verification tests.
Demonstrates:
1. Wheel successfully built.
2. Wheel successfully installed in an isolated temporary virtual environment.
3. Installed console entry point ('tsukiko') successfully executed out-of-tree.
4. Packaged resources successfully located without access to repository source tree.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
import pytest

from app.core.config.settings import find_default_config_path, load_config, reset_config

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_packaged_config_discovery():
    """Verify default_config.yaml is located and valid."""
    cfg_path = find_default_config_path()
    assert cfg_path.exists()
    assert cfg_path.name in ("default_config.yaml", "default_config.yml")

    reset_config()
    loaded = load_config(cfg_path)
    assert loaded.app.name == "Tsukiko"
    assert loaded.privacy.local_only is True


def test_wheel_build_and_contents(temp_dir):
    """Milestone 1: Build wheel from repository and verify packaged contents."""
    dist_dir = temp_dir / "wheel_dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    # Build wheel using pip wheel with current python
    build_cmd = [
        sys.executable,
        "-m",
        "pip",
        "wheel",
        "--no-deps",
        "-w",
        str(dist_dir),
        str(PROJECT_ROOT),
    ]
    res = subprocess.run(build_cmd, capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, f"Wheel build failed:\nStdout: {res.stdout}\nStderr: {res.stderr}"

    wheel_files = list(dist_dir.glob("*.whl"))
    assert len(wheel_files) == 1, "Expected exactly one built wheel file."
    wheel_path = wheel_files[0]
    assert wheel_path.name.startswith("tsukiko-")

    # Inspect wheel contents
    with zipfile.ZipFile(wheel_path, "r") as z:
        names = set(z.namelist())

        # Must contain app code and packaged config
        assert "app/__init__.py" in names
        assert "app/main.py" in names
        assert "app/core/config/default_config.yaml" in names
        assert "app/core/privacy/enforcement.py" in names
        assert "app/core/privacy/windows_firewall.py" in names
        assert "app/core/resource_manager/hardware.py" in names
        assert "app/core/resource_manager/diagnostic.py" in names

        # Must declare tsukiko console entry point
        entry_points = [n for n in names if n.endswith("entry_points.txt")]
        assert len(entry_points) == 1
        ep_content = z.read(entry_points[0]).decode("utf-8")
        assert "tsukiko = app.main:main" in ep_content

        # Must NOT leak repository development folders into wheel
        assert not any(n.startswith("scripts/") for n in names)
        assert not any(n.startswith("tests/") for n in names)


def test_genuine_wheel_installation_and_out_of_tree_execution(temp_dir):
    """Milestones 1-4: Build wheel, install in clean venv, run console command out-of-tree, and verify resources."""
    # Milestone 1: Wheel successfully built
    dist_dir = temp_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    build_cmd = [
        sys.executable,
        "-m",
        "pip",
        "wheel",
        "--no-deps",
        "-w",
        str(dist_dir),
        str(PROJECT_ROOT),
    ]
    build_res = subprocess.run(build_cmd, capture_output=True, text=True, timeout=60)
    assert build_res.returncode == 0, f"Wheel build failed:\n{build_res.stderr}"
    wheel_files = list(dist_dir.glob("*.whl"))
    assert len(wheel_files) == 1
    wheel_file = wheel_files[0]

    # Milestone 2: Wheel successfully installed into a clean isolated venv
    venv_dir = temp_dir / "isolated_venv"
    venv_cmd = [sys.executable, "-m", "venv", str(venv_dir)]
    subprocess.run(venv_cmd, check=True, timeout=30)

    scripts_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
    pip_exe = scripts_dir / ("pip.exe" if os.name == "nt" else "pip")
    python_exe = scripts_dir / ("python.exe" if os.name == "nt" else "python")
    tsukiko_cli = scripts_dir / ("tsukiko.exe" if os.name == "nt" else "tsukiko")

    # Install wheel into isolated virtual environment
    install_cmd = [str(pip_exe), "install", str(wheel_file)]
    install_res = subprocess.run(install_cmd, capture_output=True, text=True, timeout=90)
    assert install_res.returncode == 0, f"Wheel installation failed:\n{install_res.stderr}"
    assert tsukiko_cli.exists(), f"Installed console entry point not found at {tsukiko_cli}"

    # Milestone 3: Installed console entry point successfully executed outside source tree
    outside_dir = temp_dir / "outside_workspace"
    outside_dir.mkdir(parents=True, exist_ok=True)

    clean_env = dict(os.environ)
    clean_env.pop("PYTHONPATH", None)

    cli_cmd = [str(tsukiko_cli), "--check-hardware"]
    cli_res = subprocess.run(
        cli_cmd,
        cwd=str(outside_dir),
        capture_output=True,
        text=True,
        env=clean_env,
        timeout=15,
    )
    assert cli_res.returncode == 0, f"CLI execution failed with code {cli_res.returncode}:\n{cli_res.stderr}"
    assert "TSUKIKO HARDWARE & ENVIRONMENT AUDIT" in cli_res.stdout
    assert "Dynamic Safe VRAM Cap:" in cli_res.stdout

    # Milestone 4: Packaged resources successfully located and no reliance on scripts/
    verify_script = (
        "import sys\n"
        "from app.core.config.settings import find_default_config_path, load_config\n"
        "path = find_default_config_path()\n"
        "assert path.exists(), f'Config path {path} does not exist!'\n"
        "cfg = load_config(path)\n"
        "assert cfg.app.name == 'Tsukiko'\n"
        "assert cfg.privacy.local_only is True\n"
        "# Verify scripts/ module is not imported or present\n"
        "try:\n"
        "    import scripts\n"
        "    sys.exit(2)\n"
        "except ModuleNotFoundError:\n"
        "    pass\n"
        "sys.exit(0)\n"
    )

    verif_res = subprocess.run(
        [str(python_exe), "-c", verify_script],
        cwd=str(outside_dir),
        capture_output=True,
        text=True,
        env=clean_env,
        timeout=10,
    )
    assert verif_res.returncode == 0, f"Resource/isolation verification failed:\n{verif_res.stderr}"
